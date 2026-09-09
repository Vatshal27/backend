const fs = require("fs");
const path = require("path");


function getCodeContext(filePath, lineNumber, range = 5) {

    try {

        const absolutePath =
            path.resolve(filePath);


        if (!fs.existsSync(absolutePath)) {
            return "";
        }


        const content =
            fs.readFileSync(
                absolutePath,
                "utf8"
            );


        const lines =
            content.split(/\r?\n/);


        const start =
            Math.max(
                0,
                lineNumber - range - 1
            );


        const end =
            Math.min(
                lines.length,
                lineNumber + range
            );


        return lines
            .slice(start, end)
            .map((line, index) => {

                const actualLine =
                    start + index + 1;


                if (
                    actualLine >= lineNumber &&
                    actualLine <= lineNumber + 2
                ) {

                    return `>>> ${actualLine}: ${line}`;

                }


                return `${actualLine}: ${line}`;

            })
            .join("\n");


    } catch(error) {

        console.error(
            "[Context] Failed:",
            error.message
        );

        return "";

    }

}


module.exports = {
    getCodeContext
};