import js from "@eslint/js";


export default [

    {
        ...js.configs.recommended,

        languageOptions: {

            globals: {

                require: "readonly",
                module: "readonly",
                process: "readonly",
                console: "readonly"

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

            "no-unused-vars": "warn"

        }

    }

];