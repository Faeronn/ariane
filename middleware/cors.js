import cors from 'cors';

const ORIGIN = /^https?:\/\/[^/\s?#]+$/;

// CORS_ORIGINS: comma-separated browser origins allowed to call the API (the dashboard).
export const parseOrigins = (value = '') => value.split(',').map(origin => origin.trim()).filter(Boolean);
export const isValidOrigin = origin => ORIGIN.test(origin);

// Only listed origins get CORS headers; an empty list allows no cross-origin browser call.
export const createCors = origins => cors({ origin: origins.length > 0 ? origins : false });

export default createCors(parseOrigins(process.env.CORS_ORIGINS));
