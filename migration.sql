USE dual_auth_voting;

-- Safe additive migration for an existing installation.
-- Run only if notices.created_by does not already exist.
SET @col_exists := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'notices'
    AND COLUMN_NAME = 'created_by'
);

SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE notices ADD COLUMN created_by VARCHAR(100) NULL AFTER file_path',
  'SELECT 1'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
