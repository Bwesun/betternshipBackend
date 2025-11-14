-- USERS
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
	name VARCHAR(150) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(25) DEFAULT 'staff',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- FILES
CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    uploader_id INT REFERENCES users(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,  -- physical path on the server
    file_type VARCHAR(50),    -- e.g. 'pdf', 'docx', 'jpg'
    file_size BIGINT,         -- in bytes
    status VARCHAR(50) CHECK (status IN ('pending', 'approved', 'rejected')) DEFAULT 'pending',
    version INT DEFAULT 1,
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- PASSWORD RESET
CREATE TABLE IF NOT EXISTS password_resets (
  id SERIAL PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  otp_hash VARCHAR(128) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);
