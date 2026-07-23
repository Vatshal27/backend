const {
    runBandit
} = require("./scanner/bandit");


async function test(){

    try {

        const findings =
            await runBandit(
                "./semgrep-test"
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