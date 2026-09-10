import axios from 'axios';
import { normalizeApiError } from './errors';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 120000,
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const enriched = new Error(normalizeApiError(error));
    enriched.status = status;
    return Promise.reject(enriched);
  },
);

export default api;