/**
 * SentinelAI Vulnerability Testing Application
 * ---------------------------------------------
 * INTENTIONALLY VULNERABLE APPLICATION
 *
 * Purpose:
 * - Testing static analysis
 * - Testing LLM vulnerability reasoning
 * - Testing controlled sandbox simulations
 *
 * DO NOT DEPLOY.
 */

const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const cookieParser = require("cookie-parser");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");


const app = express();

const PORT = 8080;


// ------------------------------------------------
// Middleware
// ------------------------------------------------


// Vulnerability:
// Allows every origin.
app.use(cors());


// Vulnerability:
// No request size protection.
app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));


app.use(cookieParser());



// ------------------------------------------------
// Hardcoded Secrets
// ------------------------------------------------


const ADMIN_USERNAME = "admin";

const ADMIN_PASSWORD = "admin123";

const JWT_SECRET =
    "super-secret-production-key";



// ------------------------------------------------
// Database Setup
// ------------------------------------------------


const database =
    new sqlite3.Database(
        ":memory:"
    );


function initializeDatabase(){

    database.serialize(()=>{

        database.run(`
            CREATE TABLE users(
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                role TEXT
            )
        `);


        database.run(`
            INSERT INTO users
            VALUES(
                1,
                'admin',
                'admin123',
                'administrator'
            )
        `);


        database.run(`
            INSERT INTO users
            VALUES(
                2,
                'user',
                'password',
                'normal'
            )
        `);

    });

}


initializeDatabase();



// ------------------------------------------------
// File System Setup
// ------------------------------------------------


const uploadDirectory =
    path.join(
        __dirname,
        "files"
    );


if(!fs.existsSync(uploadDirectory)){
    fs.mkdirSync(uploadDirectory);
}


fs.writeFileSync(
    path.join(
        uploadDirectory,
        "public.txt"
    ),
    "Public information"
);


fs.writeFileSync(
    path.join(
        __dirname,
        "secret.txt"
    ),
    "TOP_SECRET_DATA"
);



// ------------------------------------------------
// Health Check
// ------------------------------------------------


app.get(
    "/health",
    (req,res)=>{

        res.json({
            status:"running",
            message:
            "Intentionally vulnerable server"
        });

    }
);



// ------------------------------------------------
// SQL Injection
// ------------------------------------------------


app.get(
    "/users",
    (req,res)=>{


        const username =
            req.query.username;


        // Vulnerable query construction

        const query =
        `
        SELECT *
        FROM users
        WHERE username='${username}'
        `;



        database.all(
            query,
            (error,rows)=>{


                if(error){

                    return res.status(500)
                    .json({
                        error:
                        error.message
                    });

                }


                res.json({

                    executedQuery:
                    query,

                    users:
                    rows

                });


            }
        );


    }
);



// ------------------------------------------------
// Reflected XSS
// ------------------------------------------------


app.get(
    "/profile",
    (req,res)=>{


        const name =
            req.query.name;


        // Vulnerable HTML rendering

        res.send(`
            <html>

            <body>

            <h1>
            Welcome ${name}
            </h1>

            </body>

            </html>
        `);


    }
);



// ------------------------------------------------
// Command Injection
// ------------------------------------------------


app.get(
    "/network-check",
    (req,res)=>{


        const host =
            req.query.host;



        // Vulnerable command execution

        exec(
            `ping ${host}`,
            (error,stdout,stderr)=>{


                res.json({

                    command:
                    `ping ${host}`,

                    output:
                    stdout,

                    error:
                    stderr

                });


            }
        );


    }
);



// ------------------------------------------------
// Path Traversal
// ------------------------------------------------


app.get(
    "/download",
    (req,res)=>{


        const filename =
            req.query.file;



        const filePath =
            path.join(
                uploadDirectory,
                filename
            );


        // Vulnerable file access

        fs.readFile(
            filePath,
            "utf8",
            (error,data)=>{


                if(error){

                    return res.status(404)
                    .json({
                        error:
                        error.message
                    });

                }


                res.send(data);


            }
        );


    }
);



app.get(
    "/admin-panel",
    (req,res)=>{


        res.json({

            message:
            "Admin information",

            username:
            ADMIN_USERNAME,

            password:
            ADMIN_PASSWORD,

            secret:
            JWT_SECRET

        });


    }
);

app.post(
    "/login",
    (req,res)=>{


        const username =
            req.body.username;


        const password =
            req.body.password;



        // Vulnerability:
        // Plaintext comparison

        if(
            username === ADMIN_USERNAME &&
            password === ADMIN_PASSWORD
        ){


            // Vulnerability:
            // insecure cookie

            res.cookie(
                "session",
                "admin-session",
                {

                    httpOnly:false,

                    secure:false,

                    sameSite:"none"

                }
            );


            return res.json({

                success:true,

                role:
                "administrator"

            });


        }



        res.status(401)
        .json({

            success:false,

            message:
            "Invalid credentials"

        });



    }
);

app.post(
    "/forgot-password",
    (req,res)=>{


        // No rate limiting

        res.json({

            message:
            "Password reset email sent"

        });


    }
);



// ------------------------------------------------
// Start Server
// ------------------------------------------------


app.listen(
    PORT,
    "127.0.0.1",
    ()=>{


        console.log(
        `
        Vulnerable Demo Running

        URL:
        http://127.0.0.1:${PORT}

        Available Tests:

        SQL Injection:
        /users?username=' OR '1'='1

        XSS:
        /profile?name=<script>alert(1)</script>

        Command Injection:
        /network-check?host=127.0.0.1;whoami

        Path Traversal:
        /download?file=../secret.txt

        Missing Auth:
        /admin-panel

        Login:
        POST /login

        `
        );


    }
);