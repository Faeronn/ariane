-- Applications and their code dependencies. An agent registers each application it finds on its
-- machine with the application's lockfiles; every registration is a snapshot of the exact
-- packages installed (like inventory snapshots for programs). Package keys are checked against
-- OSV in the background; their vulnerabilities live in `cve` like the NVD ones.

-- OSV ids (GHSA-xxxx-xxxx-xxxx, PYSEC-2023-74...) are stored next to CVE ids: room for them.
-- MariaDB refuses to resize a column a foreign key uses, even with FOREIGN_KEY_CHECKS = 0: the
-- cpe_cve => cve key is dropped, both sides resized, then the key is added back.
ALTER TABLE `cpe_cve` DROP FOREIGN KEY IF EXISTS `cpe_cve_ibfk_1`;
ALTER TABLE `cve` MODIFY `cveID` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL;
ALTER TABLE `cpe_cve` MODIFY `cveID` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL;
ALTER TABLE `cpe_cve` ADD CONSTRAINT `cpe_cve_ibfk_1` FOREIGN KEY IF NOT EXISTS (`cveID`) REFERENCES `cve` (`cveID`) ON DELETE CASCADE ON UPDATE RESTRICT;
ALTER TABLE `machine_cve_state` MODIFY `cveID` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL;

CREATE TABLE IF NOT EXISTS `applications` (
  `applicationID` int NOT NULL AUTO_INCREMENT,
  `orgID` int NOT NULL,
  `machineID` int NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `path` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `createdAt` datetime NOT NULL,
  `lastSeenAt` datetime NOT NULL,
  PRIMARY KEY (`applicationID`) USING BTREE,
  UNIQUE INDEX `uniq_machine_name`(`machineID`, `name`) USING BTREE,
  INDEX `idx_orgID`(`orgID`) USING BTREE,
  CONSTRAINT `applications_ibfk_1` FOREIGN KEY (`orgID`) REFERENCES `organizations` (`orgID`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `applications_ibfk_2` FOREIGN KEY (`machineID`) REFERENCES `machines` (`machineID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `application_snapshot` (
  `snapshotID` int NOT NULL AUTO_INCREMENT,
  `applicationID` int NOT NULL,
  `receivedAt` datetime NOT NULL,
  PRIMARY KEY (`snapshotID`) USING BTREE,
  INDEX `idx_applicationID`(`applicationID`) USING BTREE,
  CONSTRAINT `application_snapshot_ibfk_1` FOREIGN KEY (`applicationID`) REFERENCES `applications` (`applicationID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- One row per package of a snapshot. ecosystem: OSV name (npm, Packagist, PyPI). direct: listed by
-- the application itself; dev: development-only.
CREATE TABLE IF NOT EXISTS `application_dependency` (
  `snapshotID` int NOT NULL,
  `ecosystem` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `version` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `direct` tinyint(1) NOT NULL DEFAULT 0,
  `dev` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`snapshotID`, `ecosystem`, `name`, `version`) USING BTREE,
  INDEX `idx_package`(`ecosystem`, `name`, `version`) USING BTREE,
  CONSTRAINT `application_dependency_ibfk_1` FOREIGN KEY (`snapshotID`) REFERENCES `application_snapshot` (`snapshotID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- Shared package keys waiting for (pending) or done with (checked) their OSV query.
CREATE TABLE IF NOT EXISTS `package_vuln_key` (
  `ecosystem` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `version` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `status` enum('pending','checked') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'pending',
  `checkedAt` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`ecosystem`, `name`, `version`) USING BTREE,
  INDEX `idx_status`(`status`, `checkedAt`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

-- Vulnerabilities OSV reports for a package key, rewritten per key on each check.
CREATE TABLE IF NOT EXISTS `package_vuln` (
  `ecosystem` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `version` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `cveID` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`ecosystem`, `name`, `version`, `cveID`) USING BTREE,
  INDEX `idx_cveID`(`cveID`) USING BTREE,
  CONSTRAINT `package_vuln_ibfk_1` FOREIGN KEY (`cveID`) REFERENCES `cve` (`cveID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;
