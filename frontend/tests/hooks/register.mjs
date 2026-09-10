import { register } from 'node:module';

register(new URL('./resolve-extensions.mjs', import.meta.url).href);