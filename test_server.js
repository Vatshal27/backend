const axios = require("axios");

async function test() {

    try {

        const response =
            await axios.post(
                "http://localhost:3000/analyze-project",
                {
                    projectPath:
                    "./semgrep-test"
                }
            );


        console.log(
            JSON.stringify(
                response.data,
                null,
                2
            )
        );


    } catch(error) {

        console.error(
            error.message
        );

    }

}


test();