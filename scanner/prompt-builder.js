function buildSecurityPrompt(findings) {


    if (!findings || findings.length === 0) {

        return `
You are a security engineer.

No vulnerabilities were detected by static analysis.

Return:

{
 "findings":[]
}
`;

    }



    return `
You are a senior application security engineer.

You are given VERIFIED security findings from static analysis tools.

Your job is NOT to search for new vulnerabilities.

Do not invent issues.
Only explain the provided findings.

For every finding provide:

- Why this is dangerous
- How an attacker could abuse it
- What the impact could be
- The recommended fix


Return ONLY valid JSON.

Format:

{
 "findings":[

 {
   "vulnerability":"",
   "severity":"",
   "file":"",
   "line":"",
   "explanation":"",
   "attackStory":[
      "Step 1",
      "Step 2",
      "Step 3"
   ],
   "fix":""
 }

 ]
}


STATIC ANALYSIS FINDINGS:

${JSON.stringify(findings, null, 2)}

`;

}



module.exports = {
    buildSecurityPrompt
};