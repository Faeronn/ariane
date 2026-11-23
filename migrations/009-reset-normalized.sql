-- Resolution now tries the version as reported before its upstream form: keys matched on a
-- truncated hyphen version (ImageMagick 7.1.2-30 => 7.1.2) are resolved again.
UPDATE `software_cpe`
  SET `status` = 'pending', `cpeName` = NULL, `cpeSynthetic` = 0, `versionNormalized` = 0, `cvesCheckedAt` = NULL
  WHERE `versionNormalized` = 1 AND `version` LIKE '%-%';
