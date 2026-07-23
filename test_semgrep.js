const {
    runSemgrep
} = require("./scanner/semgrep");


async function testSemgrep() {

    try {

        const findings = await runSemgrep(
            "./semgrep-test"
        );


        console.log(
            "\n===== SENTINELAI SEMGREP RESULTS =====\n"
        );


        console.log(
            JSON.stringify(
                findings,
                null,
                2
            )
        );


    } catch(error) {


        console.error(
            "Semgrep test failed:"
        );


        console.error(
            error.message
        );


    }

}


testSemgrep();