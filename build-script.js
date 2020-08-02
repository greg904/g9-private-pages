#!/usr/env/node

const argv = require("minimist")(process.argv.slice(2));

const fs = require("fs");
const path = require("path");

function startBuild() {
    let promises = [];

    if (argv.html) {
        console.log("minifying HTML...");

        const htmlMinifier = require("html-minifier");
        
        const inputFile = path.join(__dirname, "src", "templates", "log-in.html.njk");
        const outputFile = path.join(__dirname, "dist", "templates", "log-in.html.njk");
        
        const promise = fs.promises.readFile(inputFile, { encoding: "utf-8" })
            .then(async original => {
                const minified = htmlMinifier.minify(original, {
                    caseSensitive: true,
                    collapseBooleanAttributes: true,
                    collapseWhitespace: true,
                    removeComments: true,
                    sortAttributes: true,
                    sortClassName: true,
                });
                await fs.promises.mkdir(path.dirname(outputFile), { recursive: true });
                await fs.promises.writeFile(outputFile, minified);
            });
        promises.push(promise);
    }

    if (argv.css) {
        console.log("compiling CSS...");

        const postcss = require("postcss");
        const postcssConfig = require("./postcss.config"); 
    
        const inputFile = path.join(__dirname, "src", "css", "log-in.css");
        const outputFile = path.join(__dirname, "dist", "assets", "css", "log-in.css");

        const promise = fs.promises.readFile(inputFile, { encoding: "utf-8" })
            .then(original => {
                return postcss(postcssConfig.plugins)
                    .process(original, {
                        from: inputFile,
                        to: outputFile,
                    });
            })
            .then(async result => {
                await fs.promises.mkdir(path.dirname(outputFile), { recursive: true });
                await fs.promises.writeFile(outputFile, result.css);
            });
        promises.push(promise);
    }

    if (argv.js) {
        console.log("minifying JS...");

        const googleClosureCompiler = require("google-closure-compiler");
        const compiler = new googleClosureCompiler.jsCompiler({
            compilation_level: "ADVANCED",
            env: "BROWSER",
            language_in: "ECMASCRIPT5",
            language_out: "ECMASCRIPT5",
            isolation_mode: "IIFE",
        });
        
        const inputFile = path.join(__dirname, "src", "js", "log-in.js");
        const outputFile = path.join(__dirname, "dist", "assets", "js", "log-in.js");

        const promise = fs.promises.readFile(inputFile, { encoding: "utf-8" })
            .then(original => {
                return new Promise((resolve, reject) => {
                    compiler.run([
                        {
                            src: original,
                            path: "src/js/log-in.js",
                        }
                    ], (exitCode, outputFiles, errors) => {
                        if (exitCode !== 0) {
                            reject(new Error("failed to minify JS: " + errors));
                        } else {
                            resolve(outputFiles[0].src);
                        }
                    });
                });
            })
            .then(async minified => {
                await fs.promises.mkdir(path.dirname(outputFile), { recursive: true });
                await fs.promises.writeFile(outputFile, minified);
            });
        promises.push(promise);
    }

    return promises;
}

function watchAndCopyAssets() {
    const filesToCopy = [];

    if (argv.html) {
        filesToCopy.push({
            from: path.join(__dirname, "src", "templates", "log-in.html.njk"),
            to: path.join(__dirname, "dist", "templates", "log-in.html.njk"),
        });
    }
    if (argv.css) {
        filesToCopy.push({
            from: path.join(__dirname, "src", "css", "log-in.css"),
            to: path.join(__dirname, "dist", "assets", "css", "log-in.css"),
        });
    }
    if (argv.js) {
        filesToCopy.push({
            from: path.join(__dirname, "src", "js", "log-in.js"),
            to: path.join(__dirname, "dist", "assets", "js", "log-in.js"),
        });
    }

    function copyAsset(from, to) {
        console.log(`copying asset ${from} to ${to}...`);
        fs.promises.mkdir(path.dirname(to), { recursive: true })
            .then(() => fs.promises.copyFile(from, to))
            .catch(err => console.error("failed to copy asset", err));
    }

    // Initial copy
    for (let file of filesToCopy)
        copyAsset(file.from, file.to);

    // Watch for file changes
    for (let file of filesToCopy) {
        const watcher = fs.watch(file.from);
        let delayTimeout = null;
        watcher.on("change", (_eventType, _filename) => {
            // Debounce updates
            if (delayTimeout !== null)
                return;
            delayTimeout = setTimeout(() => {
                copyAsset(file.from, file.to);
                delayTimeout = null;
            }, 200);
        });
    }
}

async function main() {
    if (argv.clean) {
        console.log("deleting build directory...");
        
        await fs.promises.rmdir(path.join(__dirname, "dist"), { recursive: true });
    }

    if (argv.watch) {
        // There is nothing to build in development mode, we can just copy the
        // files
        watchAndCopyAssets();
    } else {
        const promises = startBuild();

        // Wait for all to end, and print errors as they come
        await Promise.all(promises.map(p => p.catch(console.error)));
    }
}

main().catch(console.error);
