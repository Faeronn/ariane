-- Package aliases: an ecosystem package whose NVD product is the package itself, resolved straight
-- to that vendor/product (exact CPE, else synthetic) instead of a keyword search. Only packages
-- the NVD names as such: Symfony components are not mapped to the framework product, which would
-- copy every framework CVE onto every component (Packagist covers them precisely).
-- Each product was probed first (cpeMatchString=cpe:2.3:a:<vendor>:<product>, 2026-11-23).
CREATE TABLE IF NOT EXISTS `package_alias` (
  `ecosystem` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `packageName` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `cpeVendor` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `cpeProduct` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`ecosystem`, `packageName`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

INSERT IGNORE INTO `package_alias` (`ecosystem`, `packageName`, `cpeVendor`, `cpeProduct`) VALUES
  ('Packagist', 'twig/twig', 'symfony', 'twig'),
  ('Packagist', 'symfony/symfony', 'sensiolabs', 'symfony');

-- Keys of aliased packages are resolved again.
UPDATE `software_cpe` sc INNER JOIN `package_alias` pa ON pa.`ecosystem` = sc.`ecosystem` AND pa.`packageName` = sc.`packageName`
  SET sc.`status` = 'pending', sc.`cpeName` = NULL, sc.`cpeSynthetic` = 0, sc.`cvesCheckedAt` = NULL;
