const {
    runSemgrep
} = require("./semgrep");

const {
    runBandit
} = require("./bandit");

const {
    runESLint
} = require("./eslint");

const {
    normalizeFindings
} = require("./normalize");



async function runStaticAnalysis(projectPath) {


    console.log(
        "[Scanner] Starting parallel analysis..."
    );


    const results =
        await Promise.allSettled([

            runSemgrep(projectPath),

            runBandit(projectPath),

            runESLint(projectPath)

        ]);



    const findings = [];



    const toolNames = [
        "Semgrep",
        "Bandit",
        "ESLint"
    ];



    results.forEach(
        (result, index) => {


            if (
                result.status === "fulfilled"
            ) {


                console.log(
                    `[Scanner] ${toolNames[index]} findings: ${result.value.length}`
                );


                findings.push(
                    ...result.value
                );


            } else {


                console.error(
                    `[Scanner] ${toolNames[index]} failed:`,
                    result.reason.message
                );


            }

        }
    );



    const cleaned =
        removeDuplicates(
            findings
        );



    console.log(
        `[Scanner] Total findings after cleanup: ${cleaned.length}`
    );



    return normalizeFindings(
        cleaned
    );

}





function removeDuplicates(findings) {


    const map = new Map();



    for (const finding of findings) {


        const key =
            `${finding.file}-${finding.line}-${finding.cwe || finding.type}`;



        if (!map.has(key)) {


            map.set(
                key,
                {
                    ...finding,

                    tools: [
                        finding.tool
                    ]

                }
            );


        } else {


            const existing =
                map.get(key);



            if (
                !existing.tools.includes(
                    finding.tool
                )
            ) {

                existing.tools.push(
                    finding.tool
                );

            }



            existing.severity =
                highestSeverity(
                    existing.severity,
                    finding.severity
                );

        }

    }



    return Array.from(
        map.values()
    );

}





function highestSeverity(a, b) {


    const rank = {

        High: 3,

        Medium: 2,

        Low: 1

    };



    return rank[b] > rank[a]
        ? b
        : a;

}





module.exports = {
    runStaticAnalysis
};