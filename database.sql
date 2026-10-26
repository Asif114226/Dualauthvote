CREATE DATABASE IF NOT EXISTS dual_auth_voting CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dual_auth_voting;

CREATE TABLE IF NOT EXISTS voters (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    guardian_name VARCHAR(150) NOT NULL,
    nid VARCHAR(17) NOT NULL UNIQUE,
    division VARCHAR(100) NOT NULL,
    district VARCHAR(100) NOT NULL,
    upazila VARCHAR(100) NOT NULL,
    ward VARCHAR(50) NOT NULL,
    email VARCHAR(190) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    duress_password_hash VARCHAR(255) NOT NULL,
    otp_verified_at DATETIME NULL,
    face_descriptor LONGTEXT NULL,
    face_enrolled_at DATETIME NULL,
    biometric_verified_at DATETIME NULL,
    is_registered TINYINT(1) NOT NULL DEFAULT 1,
    has_voted TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_voter_area (division, district, upazila, ward),
    INDEX idx_voter_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS nid_documents (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    voter_id BIGINT UNSIGNED NOT NULL UNIQUE,
    front_path VARCHAR(1000) NOT NULL,
    back_path VARCHAR(1000) NOT NULL,
    status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
    rejection_reason VARCHAR(500) NULL,
    reviewed_by VARCHAR(190) NULL,
    reviewed_at DATETIME NULL,
    uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_nid_documents_voter FOREIGN KEY (voter_id) REFERENCES voters(id) ON DELETE CASCADE,
    INDEX idx_nid_status_uploaded (status, uploaded_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS otp_codes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(190) NOT NULL,
    otp_hash VARCHAR(255) NOT NULL,
    purpose ENUM('registration','login','password_reset') NOT NULL DEFAULT 'registration',
    expires_at DATETIME NOT NULL,
    attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    verified_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_otp_email_purpose (email, purpose, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS candidates (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    party VARCHAR(150) NOT NULL,
    symbol VARCHAR(255) NULL,
    position VARCHAR(100) NOT NULL DEFAULT 'Member',
    division VARCHAR(100) NULL,
    district VARCHAR(100) NULL,
    upazila VARCHAR(100) NULL,
    ward VARCHAR(50) NULL,
    photo VARCHAR(500) NULL,
    status ENUM('active','inactive') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_candidate_area (division, district, upazila, ward, status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS votes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    voter_id BIGINT UNSIGNED NOT NULL,
    candidate_id BIGINT UNSIGNED NOT NULL,
    division VARCHAR(100) NOT NULL,
    district VARCHAR(100) NOT NULL,
    upazila VARCHAR(100) NOT NULL,
    ward VARCHAR(50) NOT NULL,
    cast_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_one_vote_per_voter (voter_id),
    CONSTRAINT fk_votes_voter FOREIGN KEY (voter_id) REFERENCES voters(id),
    CONSTRAINT fk_votes_candidate FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    INDEX idx_vote_area (division, district, upazila, ward)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS election_control (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    election_name VARCHAR(200) NOT NULL DEFAULT 'National Digital Election',
    is_running TINYINT(1) NOT NULL DEFAULT 0,
    start_time DATETIME NULL,
    end_time DATETIME NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT INTO election_control (id, election_name, is_running)
VALUES (1, 'National Digital Election', 0)
ON DUPLICATE KEY UPDATE id=id;

CREATE TABLE IF NOT EXISTS notices (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    message TEXT NULL,
    file_path VARCHAR(500) NULL,
    created_by VARCHAR(100) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_notice_created (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    voter_id BIGINT UNSIGNED NULL,
    action VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    details JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_voter (voter_id),
    INDEX idx_audit_action (action)
) ENGINE=InnoDB;
