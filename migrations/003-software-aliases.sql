-- Curated aliases: lowercased display name pattern (SQL LIKE) => CPE vendor and product. Global,
-- maintained here only: they feed the software_cpe cache shared by every organization.
-- Every vendor:product was checked to exist in the NVD CPE dictionary (cpeMatchString probe, 2026-11-09).

CREATE TABLE IF NOT EXISTS `software_alias` (
  `aliasID` int NOT NULL AUTO_INCREMENT,
  `namePattern` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `vendorPattern` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NULL DEFAULT NULL,
  `cpePart` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'a',
  `cpeVendor` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  `cpeProduct` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL,
  PRIMARY KEY (`aliasID`) USING BTREE,
  UNIQUE INDEX `uniq_pattern`(`namePattern`, `vendorPattern`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_520_ci ROW_FORMAT = Dynamic;

INSERT IGNORE INTO `software_alias` (`namePattern`, `cpeVendor`, `cpeProduct`) VALUES
  ('google chrome%', 'google', 'chrome'),
  ('mozilla firefox%', 'mozilla', 'firefox'),
  ('mozilla firefox esr%', 'mozilla', 'firefox_esr'),
  ('mozilla thunderbird%', 'mozilla', 'thunderbird'),
  ('microsoft edge', 'microsoft', 'edge_chromium'),
  ('7-zip%', '7-zip', '7-zip'),
  ('notepad++%', 'notepad-plus-plus', 'notepad\\+\\+'),
  ('vlc media player%', 'videolan', 'vlc_media_player'),
  ('adobe acrobat reader%', 'adobe', 'acrobat_reader_dc'),
  ('python 3.%', 'python', 'python'),
  ('git', 'git-scm', 'git'),
  ('git version%', 'git-scm', 'git'),
  ('putty%', 'putty', 'putty'),
  ('winscp%', 'winscp', 'winscp'),
  ('zoom', 'zoom', 'zoom'),
  ('zoom workplace%', 'zoom', 'zoom'),
  ('microsoft teams%', 'microsoft', 'teams'),
  ('node.js', 'nodejs', 'node.js'),
  ('wireshark%', 'wireshark', 'wireshark'),
  ('keepass%', 'keepass', 'keepass'),
  ('filezilla client%', 'filezilla-project', 'filezilla_client'),
  ('filezilla 3.%', 'filezilla-project', 'filezilla_client'),
  ('teamviewer%', 'teamviewer', 'teamviewer'),
  ('anydesk%', 'anydesk', 'anydesk'),
  ('openssh%', 'openbsd', 'openssh'),
  ('oracle vm virtualbox%', 'oracle', 'vm_virtualbox'),
  ('vmware workstation%', 'vmware', 'workstation'),
  ('docker desktop%', 'docker', 'desktop'),
  ('microsoft visual studio code%', 'microsoft', 'visual_studio_code'),
  ('libreoffice%', 'libreoffice', 'libreoffice'),
  ('gimp%', 'gimp', 'gimp'),
  ('greenshot%', 'greenshot', 'greenshot'),
  ('foxit pdf reader%', 'foxit', 'pdf_reader'),
  ('foxit reader%', 'foxit', 'pdf_reader'),
  ('postgresql%', 'postgresql', 'postgresql'),
  ('mysql server%', 'oracle', 'mysql'),
  ('winrar%', 'rarlab', 'winrar'),
  ('curl', 'haxx', 'curl');

-- Keys that found nothing before are retried with the aliases.
UPDATE `software_cpe` SET `status` = 'pending' WHERE `status` = 'unmatched';
