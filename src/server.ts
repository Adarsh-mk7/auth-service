import { createApp } from './app';
import { config } from './config/environment';

const startServer = () => {
  const app = createApp();

  const server = app.listen(config.PORT, config.HOST, () => {
    console.log(`[auth-service] Server running at http://${config.HOST}:${config.PORT} in ${config.NODE_ENV} mode`);
  });

  const gracefulShutdown = (signal: string) => {
    console.log(`\n[auth-service] Received ${signal}. Closing server gracefully...`);
    server.close(() => {
      console.log('[auth-service] HTTP server closed.');
      process.exit(0);
    });

    // Force close if graceful shutdown takes longer than 10 seconds
    setTimeout(() => {
      console.error('[auth-service] Could not close connections in time, forcefully shutting down');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
};

// Start the server if called directly
if (require.main === module) {
  startServer();
}

export { startServer };
