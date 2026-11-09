-- Initial schema (formerly ariane.sql). Idempotent: CREATE TABLE IF NOT EXISTS, never drops.
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for cpe_cve
-- ----------------------------
CREATE TABLE IF NOT EXISTS `cpe_cve`  (
  `cpeName` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `cveID` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`cpeName`, `cveID`) USING BTREE,
  INDEX `idx_cveID`(`cveID`) USING BTREE,
  CONSTRAINT `cpe_cve_ibfk_1` FOREIGN KEY (`cveID`) REFERENCES `cve` (`cveID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for cve
-- ----------------------------
CREATE TABLE IF NOT EXISTS `cve`  (
  `cveID` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL,
  `cvssScore` decimal(3, 1) NULL DEFAULT NULL,
  `severity` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `published` datetime NULL DEFAULT NULL,
  `lastModified` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`cveID`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for domain
-- ----------------------------
CREATE TABLE IF NOT EXISTS `domain`  (
  `domainId` int NOT NULL AUTO_INCREMENT,
  `domainName` varchar(255) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  PRIMARY KEY (`domainId`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = latin1 COLLATE = latin1_swedish_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Table structure for installed_software
-- ----------------------------
CREATE TABLE IF NOT EXISTS `installed_software`  (
  `softwareID` int NOT NULL AUTO_INCREMENT,
  `snapshotID` int NOT NULL,
  `vendor` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `version` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`softwareID`) USING BTREE,
  INDEX `idx_snapshotID`(`snapshotID`) USING BTREE,
  INDEX `idx_name_version`(`name`, `version`) USING BTREE,
  CONSTRAINT `installed_software_ibfk_1` FOREIGN KEY (`snapshotID`) REFERENCES `inventory_snapshot` (`snapshotID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for inventory_snapshot
-- ----------------------------
CREATE TABLE IF NOT EXISTS `inventory_snapshot`  (
  `snapshotID` int NOT NULL AUTO_INCREMENT,
  `machineID` int NOT NULL,
  `collectedAt` datetime NOT NULL,
  `receivedAt` datetime NOT NULL,
  PRIMARY KEY (`snapshotID`) USING BTREE,
  INDEX `idx_machineID`(`machineID`) USING BTREE,
  CONSTRAINT `inventory_snapshot_ibfk_1` FOREIGN KEY (`machineID`) REFERENCES `machines` (`machineID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for machines
-- ----------------------------
CREATE TABLE IF NOT EXISTS `machines`  (
  `machineID` int NOT NULL AUTO_INCREMENT,
  `hostname` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `osFamily` enum('linux','windows') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `osVersion` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `apiKeyHash` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `createdBy` int NULL DEFAULT NULL,
  `createdAt` datetime NOT NULL,
  `lastSeenAt` datetime NULL DEFAULT NULL,
  `revokedAt` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`machineID`) USING BTREE,
  UNIQUE INDEX `uniq_apiKeyHash`(`apiKeyHash`) USING BTREE,
  INDEX `idx_createdBy`(`createdBy`) USING BTREE,
  CONSTRAINT `machines_ibfk_1` FOREIGN KEY (`createdBy`) REFERENCES `users` (`userID`) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for refresh_token
-- ----------------------------
CREATE TABLE IF NOT EXISTS `refresh_token`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `userID` int NOT NULL,
  `tokenHash` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `expiresAt` datetime NOT NULL,
  `createdAt` datetime NOT NULL,
  `lastUsedAt` datetime NULL DEFAULT NULL,
  `revokedAt` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uniq_tokenHash`(`tokenHash`) USING BTREE,
  INDEX `idx_userID`(`userID`) USING BTREE,
  CONSTRAINT `refresh_token_ibfk_1` FOREIGN KEY (`userID`) REFERENCES `users` (`userID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for software_cpe
-- ----------------------------
CREATE TABLE IF NOT EXISTS `software_cpe`  (
  `softwareCpeID` int NOT NULL AUTO_INCREMENT,
  `vendor` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `version` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',
  `cpeName` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `versionNormalized` tinyint(1) NOT NULL DEFAULT 0,
  `status` enum('pending','matched','unmatched') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'pending',
  `lastCheckedAt` datetime NULL DEFAULT NULL,
  `cvesCheckedAt` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`softwareCpeID`) USING BTREE,
  UNIQUE INDEX `uniq_software`(`vendor`, `name`, `version`) USING BTREE,
  INDEX `idx_status`(`status`, `lastCheckedAt`) USING BTREE,
  INDEX `idx_cpeName`(`cpeName`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for users
-- ----------------------------
CREATE TABLE IF NOT EXISTS `users`  (
  `userID` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `firstname` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `lastname` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `role` varchar(25) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `isVerified` tinyint NULL DEFAULT NULL,
  PRIMARY KEY (`userID`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for verifications
-- ----------------------------
CREATE TABLE IF NOT EXISTS `verifications`  (
  `verificationID` int NOT NULL AUTO_INCREMENT,
  `userID` int NOT NULL,
  `verificationCode` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `expiryDate` datetime NULL DEFAULT NULL,
  `attempts` int NOT NULL DEFAULT 0,
  PRIMARY KEY (`verificationID`) USING BTREE,
  UNIQUE INDEX `uniq_userID`(`userID`) USING BTREE,
  CONSTRAINT `verifications_ibfk_1` FOREIGN KEY (`userID`) REFERENCES `users` (`userID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
