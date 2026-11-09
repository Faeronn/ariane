-- Organizations: every allowed email domain, user and machine belongs to one. Roles admin/viewer.
-- Backfill: one organization per existing domain, users by their email domain, machines by their
-- creator's organization, and the earliest verified user of each organization becomes admin.

CREATE TABLE IF NOT EXISTS `organizations` (
  `orgID` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `createdAt` datetime NOT NULL,
  PRIMARY KEY (`orgID`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- Domains: a domain without a name can never match a signup.
DELETE FROM `domain` WHERE `domainName` IS NULL OR `domainName` = '';
ALTER TABLE `domain` ADD COLUMN IF NOT EXISTS `orgID` int NULL;
INSERT INTO `organizations` (`name`, `createdAt`)
  SELECT CONVERT(d.`domainName` USING utf8mb4), UTC_TIMESTAMP() FROM `domain` d WHERE d.`orgID` IS NULL;
UPDATE `domain` d INNER JOIN `organizations` o ON o.`name` = CONVERT(d.`domainName` USING utf8mb4)
  SET d.`orgID` = o.`orgID` WHERE d.`orgID` IS NULL;
ALTER TABLE `domain`
  MODIFY `orgID` int NOT NULL,
  ADD INDEX IF NOT EXISTS `idx_orgID` (`orgID`),
  ADD CONSTRAINT `domain_ibfk_1` FOREIGN KEY IF NOT EXISTS (`orgID`) REFERENCES `organizations` (`orgID`) ON DELETE CASCADE ON UPDATE RESTRICT;

-- Users: organization from the email domain (NULL when the domain was removed: refused at sign-in).
ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `orgID` int NULL AFTER `userID`;
UPDATE `users` u INNER JOIN `domain` d ON CONVERT(d.`domainName` USING utf8mb4) = SUBSTRING_INDEX(u.`username`, '@', -1)
  SET u.`orgID` = d.`orgID` WHERE u.`orgID` IS NULL;
UPDATE `users` SET `role` = 'viewer' WHERE `role` IS NULL OR `role` NOT IN ('admin', 'viewer');
ALTER TABLE `users`
  MODIFY `role` enum('admin','viewer') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'viewer',
  ADD INDEX IF NOT EXISTS `idx_orgID` (`orgID`),
  ADD CONSTRAINT `users_ibfk_1` FOREIGN KEY IF NOT EXISTS (`orgID`) REFERENCES `organizations` (`orgID`) ON DELETE SET NULL ON UPDATE RESTRICT;
UPDATE `users` u INNER JOIN (
    SELECT f.`orgID`, MIN(f.`userID`) AS `userID` FROM `users` f
    WHERE f.`isVerified` = 1 AND f.`orgID` IS NOT NULL
      AND f.`orgID` NOT IN (SELECT a.`orgID` FROM `users` a WHERE a.`role` = 'admin' AND a.`orgID` IS NOT NULL)
    GROUP BY f.`orgID`
  ) firsts ON firsts.`userID` = u.`userID`
  SET u.`role` = 'admin';

-- Machines: the creator's organization, else the oldest organization.
ALTER TABLE `machines` ADD COLUMN IF NOT EXISTS `orgID` int NULL AFTER `machineID`;
UPDATE `machines` m INNER JOIN `users` u ON u.`userID` = m.`createdBy` SET m.`orgID` = u.`orgID` WHERE m.`orgID` IS NULL;
UPDATE `machines` SET `orgID` = (SELECT MIN(`orgID`) FROM `organizations`) WHERE `orgID` IS NULL;
ALTER TABLE `machines`
  MODIFY `orgID` int NOT NULL,
  ADD INDEX IF NOT EXISTS `idx_orgID` (`orgID`),
  ADD CONSTRAINT `machines_ibfk_2` FOREIGN KEY IF NOT EXISTS (`orgID`) REFERENCES `organizations` (`orgID`) ON DELETE CASCADE ON UPDATE RESTRICT;
