const {
    runStaticAnalysis
} = require("./scanner/scanner");



async function test(){


    const findings =
        await runStaticAnalysis(
            "./semgrep-test"
        );



    console.log(
        "\n===== SENTINELAI FINAL RESULTS =====\n"
    );


    console.log(
        JSON.stringify(
            findings,
            null,
            2
        )
    );


}



test();