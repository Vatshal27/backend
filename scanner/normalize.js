const {
    getCodeContext
} = require("./context");


function normalizeFindings(findings) {

    return findings.map(finding => {

        return {

            vulnerability:
                finding.type ||
                "Security Issue",


            severity:
                normalizeSeverity(
                    finding.severity
                ),


            confidence:
                calculateConfidence(
                    finding
                ),


            location: {

                file:
                    finding.file ||
                    "Unknown",


                line:
                    finding.line ||
                    0

            },


            cwe:
                finding.cwe ||
                "",


            evidence:
                finding.message ||
                "",


            codeContext:
                getCodeContext(
                    finding.file,
                    Number(
                        finding.line
                    )
                ),


            tools:
                finding.tools ||
                [
                    finding.tool
                ]

        };

    });

}





function normalizeSeverity(level) {


    if (!level)
        return "Low";


    return level;

}





function calculateConfidence(finding) {


    const highConfidence = [

        "SQL Injection",

        "Command Injection",

        "Shell Injection",

        "Code Injection",

        "Dangerous Eval"

    ];



    if (
        highConfidence.includes(
            finding.type
        )
    ) {

        return "High";

    }



    if (
        finding.severity === "High"
    ) {

        return "Medium";

    }



    return "Low";

}





module.exports = {
    normalizeFindings
};