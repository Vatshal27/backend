const express = require("express");
const mysql = require("mysql");
const { exec } = require("child_process");

const app = express();


// -------------------------
// SQL Injection
// -------------------------

app.get("/user", (req, res) => {

    const id = req.query.id;

    const query =
        "SELECT * FROM users WHERE id=" + id;


    mysql.query(query, (err,result)=>{

        res.json(result);

    });

});



// -------------------------
// Command Injection
// -------------------------

app.get("/ping",(req,res)=>{


    const host =
        req.query.host;


    exec(
        "ping " + host,
        (error,stdout)=>{

            res.send(stdout);

        }
    );


});



// -------------------------
// XSS
// -------------------------

app.get("/profile",(req,res)=>{


    const name =
        req.query.name;


    res.send(
        `
        <html>
        <body>
        <h1>Hello ${name}</h1>
        </body>
        </html>
        `
    );


});



// -------------------------
// Dangerous Eval
// -------------------------

app.get("/calculate",(req,res)=>{


    const expression =
        req.query.expression;


    const result =
        eval(expression);


    res.send(
        String(result)
    );


});


app.listen(3000);