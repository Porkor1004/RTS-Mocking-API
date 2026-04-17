const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'mock-secret-key-change-me';
const DEFAULT_TOKEN_TTL = process.env.JWT_EXPIRES_IN || '30m';
const LOGIN_MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 5);
const LOGIN_WINDOW_MINUTES = Number(process.env.LOGIN_WINDOW_MINUTES || 15);

const RESTAURANT_PROFILE = {
  name: 'TableReserve Restaurant',
  contactNumber: '02-123-4567',
  openingTime: '10:00',
  closingTime: '22:00',
  address: '123 Main Street, Bangkok 10110'
};

const tables = [
  { tableId: 1, code: 'T-01', capacity: 2, status: 'AVAILABLE' },
  { tableId: 2, code: 'T-02', capacity: 4, status: 'OCCUPIED' },
  { tableId: 3, code: 'T-03', capacity: 6, status: 'AVAILABLE' },
  { tableId: 4, code: 'T-04', capacity: 4, status: 'OUT_OF_SERVICE' },
  { tableId: 5, code: 'T-05', capacity: 8, status: 'AVAILABLE' }
];

const users = [
  {
    userId: 101,
    fullName: 'John Smith',
    email: 'john@email.com',
    password: 'Password123',
    phoneNumber: '0812345678',
    role: 'Customer'
  },
  {
    userId: 201,
    fullName: 'Sara Lee',
    email: 'staff@restaurant.com',
    password: 'Staff123A',
    phoneNumber: '0899999999',
    role: 'Staff'
  },
  {
    userId: 301,
    fullName: 'Admin User',
    email: 'admin@restaurant.com',
    password: 'Admin123A',
    phoneNumber: '0888888888',
    role: 'Admin'
  }
];

let reservations = [
  {
    reservationId: 5001,
    customerId: 101,
    customerName: 'John Smith',
    date: '2026-05-20',
    time: '18:00',
    guestCount: 4,
    tableId: 3,
    status: 'CONFIRMED',
    specialRequest: 'Window seat',
    createdByRole: 'Customer'
  },
  {
    reservationId: 5000,
    customerId: 102,
    customerName: 'Amy Park',
    date: '2026-05-20',
    time: '19:00',
    guestCount: 2,
    tableId: 1,
    status: 'CONFIRMED',
    specialRequest: '',
    createdByRole: 'Customer'
  },
  {
    reservationId: 4999,
    customerId: null,
    customerName: 'Walk-in',
    date: '2026-05-20',
    time: '12:30',
    guestCount: 3,
    tableId: 2,
    status: 'WALK-IN',
    specialRequest: '',
    createdByRole: 'Staff'
  }
];

let nextReservationId = 5002;
let nextUserId = 302;
const loginAttempts = new Map();

function responseError(res, status, message, details) {
  return res.status(status).json({
    message,
    ...(details ? { details } : {})
  });
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
  return /^\d{10,15}$/.test(phone);
}

function isValidPassword(password) {
  return /^(?=.*[A-Z])(?=.*\d).{8,20}$/.test(password);
}

function isValidFullName(fullName) {
  return /^[A-Za-z ]{2,60}$/.test(fullName);
}

function isValidDate(date) {
  return /^\d{4}-\d{2}-\d{2}$/.test(date) && !Number.isNaN(new Date(`${date}T00:00:00`).getTime());
}

function isValidTime(time) {
  return /^([01]\d|2[0-3]):([0-5]\d)$/.test(time);
}

function isFutureDateTime(date, time) {
  const dt = new Date(`${date}T${time}:00`);
  return dt.getTime() > Date.now();
}

function isWithinOperatingHours(time) {
  return time >= RESTAURANT_PROFILE.openingTime && time <= RESTAURANT_PROFILE.closingTime;
}

function containsSuspiciousInput(value) {
  if (typeof value !== 'string') return false;
  const patterns = [/<script/i, /javascript:/i, /onerror\s*=/i, /onload\s*=/i, /<img/i];
  return patterns.some((pattern) => pattern.test(value));
}

function sanitizeReservation(reservation) {
  const table = tables.find((item) => item.tableId === reservation.tableId);
  return {
    reservationId: reservation.reservationId,
    customerName: reservation.customerName,
    tableId: reservation.tableId,
    tableCode: table?.code || null,
    date: reservation.date,
    time: reservation.time,
    guestCount: reservation.guestCount,
    status: reservation.status,
    specialRequest: reservation.specialRequest
  };
}

function signToken(user, ttl = DEFAULT_TOKEN_TTL) {
  return jwt.sign(
    {
      sub: String(user.userId),
      email: user.email,
      role: user.role,
      fullName: user.fullName
    },
    JWT_SECRET,
    { expiresIn: ttl }
  );
}

function auth(requiredRoles = []) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) {
      return responseError(res, 401, 'Authentication required');
    }

    const token = header.replace('Bearer ', '').trim();
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      if (requiredRoles.length && !requiredRoles.includes(decoded.role)) {
        return responseError(res, 403, 'Access denied');
      }
      next();
    } catch (error) {
      return responseError(res, 401, 'Invalid or expired token');
    }
  };
}

function getLoginAttemptRecord(email) {
  const now = Date.now();
  const windowMs = LOGIN_WINDOW_MINUTES * 60 * 1000;
  const record = loginAttempts.get(email) || { count: 0, firstAttemptAt: now, lockedUntil: 0 };

  if (now - record.firstAttemptAt > windowMs) {
    record.count = 0;
    record.firstAttemptAt = now;
    record.lockedUntil = 0;
    loginAttempts.set(email, record);
  }

  return record;
}

function getLoginLockState(email) {
  const now = Date.now();
  const record = getLoginAttemptRecord(email);
  if (record.lockedUntil && record.lockedUntil > now) {
    return { locked: true, retryAfterSeconds: Math.ceil((record.lockedUntil - now) / 1000) };
  }
  return { locked: false, retryAfterSeconds: 0 };
}

function recordFailedLogin(email) {
  const now = Date.now();
  const windowMs = LOGIN_WINDOW_MINUTES * 60 * 1000;
  const record = getLoginAttemptRecord(email);

  record.count += 1;
  if (record.count >= LOGIN_MAX_ATTEMPTS) {
    record.lockedUntil = now + windowMs;
  }
  loginAttempts.set(email, record);

  return {
    locked: record.lockedUntil > now,
    attempts: record.count,
    retryAfterSeconds: record.lockedUntil > now ? Math.ceil((record.lockedUntil - now) / 1000) : 0
  };
}

function clearLoginAttempts(email) {
  loginAttempts.delete(email);
}

function findAvailableTables(date, time, guestCount) {
  return tables.filter((table) => {
    if (table.status !== 'AVAILABLE') return false;
    if (table.capacity < guestCount) return false;

    const doubleBooked = reservations.some((reservation) => {
      return (
        reservation.status !== 'CANCELLED' &&
        reservation.date === date &&
        reservation.time === time &&
        reservation.tableId === table.tableId
      );
    });

    return !doubleBooked;
  });
}

app.get('/', (req, res) => {
  res.json({
    message: 'Restaurant Reservation Mock API is running',
    baseUrl: `http://localhost:${PORT}`,
    mockNotes: [
      'Use POST /auth/login to get a bearer token',
      'Use ?ttl=10s on login to simulate fast token expiration for testing'
    ]
  });
});

app.post('/auth/register', (req, res) => {
  const { fullName, email, password, phoneNumber } = req.body || {};

  if (!fullName || !email || !password) {
    return responseError(res, 400, 'Invalid input data', 'fullName, email, and password are required');
  }
  if (!isValidFullName(fullName)) {
    return responseError(res, 400, 'Invalid input data', 'fullName must be 2-60 letters and spaces only');
  }
  if (!isValidEmail(email)) {
    return responseError(res, 400, 'Invalid input data', 'email format is invalid');
  }
  if (!isValidPassword(password)) {
    return responseError(res, 400, 'Invalid input data', 'password must be 8-20 chars with at least 1 uppercase and 1 number');
  }
  if (phoneNumber && !isValidPhone(phoneNumber)) {
    return responseError(res, 400, 'Invalid input data', 'phoneNumber must be 10-15 digits');
  }
  if (containsSuspiciousInput(fullName) || containsSuspiciousInput(email)) {
    return responseError(res, 400, 'Invalid input data', 'Suspicious input detected');
  }
  if (users.some((user) => user.email.toLowerCase() === String(email).toLowerCase())) {
    return responseError(res, 409, 'Email already exists');
  }

  const newUser = {
    userId: nextUserId++,
    fullName,
    email,
    password,
    phoneNumber: phoneNumber || '',
    role: 'Customer'
  };

  users.push(newUser);

  return res.status(201).json({
    userId: newUser.userId,
    message: 'Registration successful'
  });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const ttl = req.query.ttl || DEFAULT_TOKEN_TTL;

  if (!email || !password) {
    return responseError(res, 400, 'Invalid input data', 'email and password are required');
  }

  const lockState = getLoginLockState(email);
  if (lockState.locked) {
    return res.status(429).json({
      message: 'Too many failed login attempts',
      retryAfterSeconds: lockState.retryAfterSeconds
    });
  }

  const user = users.find((item) => item.email.toLowerCase() === String(email).toLowerCase());
  if (!user || user.password !== password) {
    const failedState = recordFailedLogin(email);
    return res.status(failedState.locked ? 429 : 401).json({
      message: failedState.locked ? 'Too many failed login attempts' : 'Invalid credentials',
      ...(failedState.retryAfterSeconds ? { retryAfterSeconds: failedState.retryAfterSeconds } : {})
    });
  }

  clearLoginAttempts(email);
  const token = signToken(user, ttl);
  return res.json({
    token,
    role: user.role,
    user: {
      userId: user.userId,
      fullName: user.fullName,
      email: user.email
    }
  });
});

app.get('/tables', (req, res) => {
  const { date, time, guestCount } = req.query;

  if (date || time || guestCount) {
    if (!date || !time || !guestCount) {
      return responseError(res, 400, 'Invalid input data', 'date, time, and guestCount are required together');
    }
    if (!isValidDate(date) || !isValidTime(time)) {
      return responseError(res, 400, 'Invalid input data', 'date or time format is invalid');
    }

    const guestCountNumber = Number(guestCount);
    if (!Number.isInteger(guestCountNumber) || guestCountNumber < 1 || guestCountNumber > 10) {
      return responseError(res, 400, 'Invalid input data', 'guestCount must be between 1 and 10');
    }

    const available = findAvailableTables(date, time, guestCountNumber).map((table) => ({
      tableId: table.tableId,
      code: table.code,
      capacity: table.capacity,
      status: table.status
    }));

    return res.json({
      date,
      time,
      guestCount: guestCountNumber,
      availableTables: available
    });
  }

  return res.json(tables);
});

app.post('/reservations', auth(['Customer', 'Staff', 'Admin']), (req, res) => {
  const { date, time, guestCount, specialRequest, tableId } = req.body || {};
  const guestCountNumber = Number(guestCount);

  if (!date || !time || !guestCount || !tableId) {
    return responseError(res, 400, 'Invalid input data', 'date, time, guestCount, and tableId are required');
  }
  if (!isValidDate(date) || !isValidTime(time)) {
    return responseError(res, 400, 'Invalid input data', 'date or time format is invalid');
  }
  if (!Number.isInteger(guestCountNumber) || guestCountNumber < 1 || guestCountNumber > 10) {
    return responseError(res, 400, 'Invalid input data', 'guestCount must be between 1 and 10');
  }
  if (!isFutureDateTime(date, time)) {
    return responseError(res, 400, 'Invalid input data', 'Reservation must be future date/time');
  }
  if (!isWithinOperatingHours(time)) {
    return responseError(res, 400, 'Invalid input data', 'Reservation must be within operating hours');
  }
  if (specialRequest && String(specialRequest).length > 200) {
    return responseError(res, 400, 'Invalid input data', 'specialRequest max length is 200');
  }
  if (specialRequest && containsSuspiciousInput(specialRequest)) {
    return responseError(res, 400, 'Invalid input data', 'Suspicious input detected in specialRequest');
  }

  const table = tables.find((item) => item.tableId === Number(tableId));
  if (!table) {
    return responseError(res, 404, 'Table not found');
  }
  if (table.status !== 'AVAILABLE') {
    return responseError(res, 409, 'Table not available');
  }
  if (guestCountNumber > table.capacity) {
    return responseError(res, 400, 'Invalid input data', 'Guest count must not exceed table capacity');
  }

  const isDoubleBooked = reservations.some((reservation) => {
    return (
      reservation.status !== 'CANCELLED' &&
      reservation.date === date &&
      reservation.time === time &&
      reservation.tableId === Number(tableId)
    );
  });

  if (isDoubleBooked) {
    return responseError(res, 409, 'Table not available');
  }

  const customerId = req.user.role === 'Customer' ? Number(req.user.sub) : null;
  const reservation = {
    reservationId: nextReservationId++,
    customerId,
    customerName: req.user.fullName,
    date,
    time,
    guestCount: guestCountNumber,
    tableId: Number(tableId),
    status: req.user.role === 'Staff' ? 'WALK-IN' : 'CONFIRMED',
    specialRequest: specialRequest || '',
    createdByRole: req.user.role
  };

  reservations.unshift(reservation);

  return res.status(201).json({
    reservationId: reservation.reservationId,
    status: reservation.status
  });
});

app.get('/reservations/my', auth(['Customer']), (req, res) => {
  const myReservations = reservations
    .filter((reservation) => reservation.customerId === Number(req.user.sub))
    .map(sanitizeReservation);

  return res.json(myReservations);
});

app.delete('/reservations/:reservationId', auth(['Customer', 'Staff', 'Admin']), (req, res) => {
  const reservationId = Number(req.params.reservationId);
  const reservation = reservations.find((item) => item.reservationId === reservationId);

  if (!reservation) {
    return responseError(res, 404, 'Reservation not found');
  }

  if (req.user.role === 'Customer' && reservation.customerId !== Number(req.user.sub)) {
    return responseError(res, 403, 'Access denied');
  }

  if (req.user.role === 'Customer') {
    const reservationDateTime = new Date(`${reservation.date}T${reservation.time}:00`).getTime();
    const oneHourBefore = reservationDateTime - 60 * 60 * 1000;
    if (Date.now() > oneHourBefore) {
      return responseError(res, 400, 'Cancellation allowed only at least 1 hour before reservation time');
    }
  }

  reservation.status = 'CANCELLED';
  return res.json({ message: 'Reservation cancelled' });
});

app.get('/admin/reservations', auth(['Admin']), (req, res) => {
  return res.json(reservations.map(sanitizeReservation));
});

app.post('/staff/walkins', auth(['Staff', 'Admin']), (req, res) => {
  const { customerName, date, time, guestCount, tableId } = req.body || {};
  if (!customerName) {
    return responseError(res, 400, 'Invalid input data', 'customerName is required');
  }
  req.body.specialRequest = '';
  req.body.tableId = tableId;
  req.body.date = date;
  req.body.time = time;
  req.body.guestCount = guestCount;

  const guestCountNumber = Number(guestCount);
  if (!isValidDate(date) || !isValidTime(time)) {
    return responseError(res, 400, 'Invalid input data', 'date or time format is invalid');
  }
  if (!Number.isInteger(guestCountNumber) || guestCountNumber < 1 || guestCountNumber > 10) {
    return responseError(res, 400, 'Invalid input data', 'guestCount must be between 1 and 10');
  }

  const table = tables.find((item) => item.tableId === Number(tableId));
  if (!table || table.status !== 'AVAILABLE' || guestCountNumber > table.capacity) {
    return responseError(res, 409, 'Table not available');
  }

  const isDoubleBooked = reservations.some((reservation) =>
    reservation.status !== 'CANCELLED' &&
    reservation.date === date &&
    reservation.time === time &&
    reservation.tableId === Number(tableId)
  );

  if (isDoubleBooked) {
    return responseError(res, 409, 'Table not available');
  }

  const reservation = {
    reservationId: nextReservationId++,
    customerId: null,
    customerName,
    date,
    time,
    guestCount: guestCountNumber,
    tableId: Number(tableId),
    status: 'WALK-IN',
    specialRequest: '',
    createdByRole: req.user.role
  };
  reservations.unshift(reservation);

  return res.status(201).json({
    reservationId: reservation.reservationId,
    status: reservation.status
  });
});

app.patch('/tables/:tableId/status', auth(['Staff', 'Admin']), (req, res) => {
  const tableId = Number(req.params.tableId);
  const { status } = req.body || {};
  const allowed = ['AVAILABLE', 'OCCUPIED', 'OUT_OF_SERVICE'];
  const table = tables.find((item) => item.tableId === tableId);

  if (!table) {
    return responseError(res, 404, 'Table not found');
  }
  if (!allowed.includes(status)) {
    return responseError(res, 400, 'Invalid input data', `status must be one of: ${allowed.join(', ')}`);
  }

  table.status = status;
  return res.json({
    tableId: table.tableId,
    code: table.code,
    status: table.status
  });
});

app.patch('/admin/restaurant-profile', auth(['Admin']), (req, res) => {
  const { name, contactNumber, openingTime, closingTime, address } = req.body || {};

  if (name !== undefined) {
    if (!String(name).trim()) return responseError(res, 400, 'Invalid input data', 'name cannot be empty');
    RESTAURANT_PROFILE.name = String(name).trim();
  }
  if (contactNumber !== undefined) {
    if (!isValidPhone(String(contactNumber))) return responseError(res, 400, 'Invalid input data', 'contactNumber must be 10-15 digits');
    RESTAURANT_PROFILE.contactNumber = String(contactNumber);
  }
  if (openingTime !== undefined) {
    if (!isValidTime(String(openingTime))) return responseError(res, 400, 'Invalid input data', 'openingTime format invalid');
    RESTAURANT_PROFILE.openingTime = String(openingTime);
  }
  if (closingTime !== undefined) {
    if (!isValidTime(String(closingTime))) return responseError(res, 400, 'Invalid input data', 'closingTime format invalid');
    RESTAURANT_PROFILE.closingTime = String(closingTime);
  }
  if (address !== undefined) {
    RESTAURANT_PROFILE.address = String(address).trim();
  }

  return res.json(RESTAURANT_PROFILE);
});

app.get('/admin/restaurant-profile', auth(['Admin']), (req, res) => {
  return res.json(RESTAURANT_PROFILE);
});

app.use((req, res) => {
  return responseError(res, 404, 'Endpoint not found');
});

app.listen(PORT, () => {
  console.log(`Mock API running on http://localhost:${PORT}`);
});