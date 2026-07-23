const {
    runESLint
} = require("./scanner/eslint");


async function test(){

    try {

        const findings =
            await runESLint(
                "./semgrep-test/vulnerable.js"
            );


        console.log(
            JSON.stringify(
                findings,
                null,
                2
            )
        );


    } catch(error){

        console.error(
            error.message
        );

    }

}


test();