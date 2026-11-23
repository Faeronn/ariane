-- OSV ids already resolved to the vulnerability row they are stored under (their single CVE alias,
-- or themselves): a known id is linked without fetching its record again.
CREATE TABLE IF NOT EXISTS `osv_alias` (
  `osvID` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `cveID` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`osvID`) USING BTREE,
  INDEX `idx_cveID`(`cveID`) USING BTREE,
  CONSTRAINT `osv_alias_ibfk_1` FOREIGN KEY (`cveID`) REFERENCES `cve` (`cveID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;
