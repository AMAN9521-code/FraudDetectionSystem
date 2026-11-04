-- RADAR Fraud Detection System - database schema
-- Works on MySQL 8 (local, Aiven, etc). Run against an EXISTING database;
-- do not add CREATE DATABASE/USE (Aiven's default database is "defaultdb").

CREATE TABLE IF NOT EXISTS `users` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('ADMIN','USER') NOT NULL DEFAULT 'USER',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `login_history` (
  `login_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `login_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `ip_address` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`login_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `login_history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `transactions` (
  `transaction_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `amount` decimal(12,2) NOT NULL,
  `merchant` varchar(150) NOT NULL,
  `location` varchar(150) NOT NULL,
  `txn_timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `status` enum('PENDING','APPROVED','FLAGGED') NOT NULL DEFAULT 'PENDING',
  `risk_score` double DEFAULT '0',
  `source_reference` varchar(150) DEFAULT NULL,
  PRIMARY KEY (`transaction_id`),
  UNIQUE KEY `uq_user_source_reference` (`user_id`,`source_reference`),
  CONSTRAINT `transactions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `fraud_alerts` (
  `alert_id` int NOT NULL AUTO_INCREMENT,
  `transaction_id` int NOT NULL,
  `reason` varchar(255) NOT NULL,
  `risk_score` double NOT NULL DEFAULT '0',
  `review_status` enum('OPEN','CONFIRMED_FRAUD','FALSE_POSITIVE') NOT NULL DEFAULT 'OPEN',
  `reviewed_by` int DEFAULT NULL,
  `reviewed_at` timestamp NULL DEFAULT NULL,
  `amount_score` double NOT NULL DEFAULT '0',
  `velocity_score` double NOT NULL DEFAULT '0',
  `location_score` double NOT NULL DEFAULT '0',
  `zscore_score` double NOT NULL DEFAULT '0',
  `ml_score` double NOT NULL DEFAULT '0',
  PRIMARY KEY (`alert_id`),
  UNIQUE KEY `uq_fraud_alert_transaction` (`transaction_id`),
  KEY `reviewed_by` (`reviewed_by`),
  CONSTRAINT `fraud_alerts_ibfk_1` FOREIGN KEY (`transaction_id`) REFERENCES `transactions` (`transaction_id`) ON DELETE CASCADE,
  CONSTRAINT `fraud_alerts_ibfk_2` FOREIGN KEY (`reviewed_by`) REFERENCES `users` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `detection_config` (
  `config_id` int NOT NULL AUTO_INCREMENT,
  `amount_threshold` decimal(12,2) NOT NULL DEFAULT '50000.00',
  `velocity_limit` int NOT NULL DEFAULT '5',
  `velocity_window_minutes` int NOT NULL DEFAULT '10',
  `zscore_threshold` double NOT NULL DEFAULT '3',
  `updated_by` int NOT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`config_id`),
  KEY `updated_by` (`updated_by`),
  CONSTRAINT `detection_config_ibfk_1` FOREIGN KEY (`updated_by`) REFERENCES `users` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `algorithm_params` (
  `param_id` int NOT NULL AUTO_INCREMENT,
  `param_name` varchar(100) NOT NULL,
  `param_value` varchar(255) NOT NULL,
  `last_feedback_score` double DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`param_id`),
  UNIQUE KEY `param_name` (`param_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `audit_log` (
  `log_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `action` varchar(255) NOT NULL,
  `log_timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`log_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `audit_log_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Starting rule weights (the app's admin page and alert reviews update these rows)
INSERT IGNORE INTO `algorithm_params` (`param_name`, `param_value`) VALUES
  ('AMOUNT_RULE_WEIGHT',   '0.30'),
  ('VELOCITY_RULE_WEIGHT', '0.25'),
  ('LOCATION_RULE_WEIGHT', '0.20'),
  ('ZSCORE_RULE_WEIGHT',   '0.25');
