const js = require("@eslint/js");
const unicorn = require("eslint-plugin-unicorn").default ?? require("eslint-plugin-unicorn");
const sonarjs = require("eslint-plugin-sonarjs").default ?? require("eslint-plugin-sonarjs");

module.exports = [
	unicorn.configs.recommended,
  	sonarjs.configs.recommended,
  	js.configs.recommended,
	{
		files: ["**/*.js"],
		rules: {
			'sonarjs/no-implicit-dependencies': 'error',
			"no-unused-vars": "warn",
			"no-undef": "warn",
		},
	},
];
