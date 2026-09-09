import js from "@eslint/js";
import globals from "globals";

export default [
    {
        ...js.configs.recommended,

        languageOptions: {
            globals: {
                ...globals.node
            }
        }
    },

    {
        files: [
            "**/*.js"
        ],

        rules: {
            "no-eval": "error",
            "no-implied-eval": "error",
            "no-control-regex": "off",
            "no-unused-vars": "warn"
        }
    }
];