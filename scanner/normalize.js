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


    /*
       Exact dangerous patterns:
       High confidence
    */


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



    /*
       Generic warnings:
       Lower confidence
    */


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