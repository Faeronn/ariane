// Apply pending schema migrations to DB_NAME: `npm run migrate`.
import { migrate } from '../utils/migrate.js';
import logger from '../utils/logger.js';

try {
	const applied = await migrate();
	logger.info({ database: process.env.DB_NAME, applied }, applied.length > 0 ? 'Migrations applied' : 'Database already up to date');
} catch (error) {
	logger.error(error, 'Migration failed');
	process.exitCode = 1;
}
