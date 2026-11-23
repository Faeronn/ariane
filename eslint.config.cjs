const js = require("@eslint/js");
const globals = require("globals");
const unicorn = require("eslint-plugin-unicorn").default ?? require("eslint-plugin-unicorn");
const sonarjs = require("eslint-plugin-sonarjs").default ?? require("eslint-plugin-sonarjs");

module.exports = [
	// Project docs and plans, including throwaway validation scripts, are not application code.
	{ ignores: ["aidd_docs/**"] },
	unicorn.configs.recommended,
  	sonarjs.configs.recommended,
  	js.configs.recommended,
	{
		files: ["**/*.js"],
		languageOptions: {
			globals: globals.node,
		},
		rules: {
			'sonarjs/no-implicit-dependencies': 'error',
			'sonarjs/todo-tag': 'warn',
			"no-unused-vars": "warn",
			"no-undef": "warn",
		},
	},
];
