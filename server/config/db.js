const { Pool } = require("pg");
const path = require('path');

// Load environment variables from the correct location
require('dotenv').config({ path: path.join(__dirname, '../../.env') });

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'threatforge_soc',
  password: process.env.DB_PASSWORD || 'postgres',
  port: parseInt(process.env.DB_PORT) || 5432,
  // Add connection timeout and retry logic
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  max: 20 // Maximum number of clients in the pool
});

// Test the connection on startup
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database connection failed:');
    console.error('   Error:', err.message);
    console.error('   Check your PostgreSQL server is running');
    console.error('   and the database credentials are correct.');
  } else {
    console.log('✅ Database connected successfully');
    release();
  }
});

// Handle pool errors
pool.on('error', (err) => {
  console.error('❌ Unexpected database pool error:', err.message);
});

module.exports = pool;