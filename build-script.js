#!/usr/env/node

"use strict";

const argv = require("minimist")(process.argv.slice(2));

const fs = require("fs");
const path = require("path");

const CSS_SRC_DIR = path.join(__dirname, "src", "css");
const CSS_OUT_DIR = path.join(__dirname, "dist", "assets", "css");

const JS_SRC_DIR = path.join(__dirname, "src", "js");
const JS_OUT_DIR = path.join(__dirname, "dist", "assets", "js");

const TEMPLATES_SRC_DIR = path.join(__dirname, "src", "templates");
const TEMPLATES_OUT_DIR = path.join(__dirname, "dist", "templates");

async function getCssFiles() {
    return fs.promises.readdir(CSS_SRC_DIR);
}

async function getJsFiles() {
    return fs.promises.readdir(JS_SRC_DIR);
}

async function getTemplateFiles() {
    return fs.promises.readdir(TEMPLATES_SRC_DIR);
}

async function minifyHtml() {
    console.log("minifying HTML...");

    const baseNames = await getTemplateFiles();
    return baseNames.map(async (baseName) => {
        const inputFile = path.join(TEMPLATES_SRC_DIR, baseName);
        const outputFile = path.join(TEMPLATES_OUT_DIR, baseName);

        const original = await fs.promises.readFile(inputFile, { encoding: "utf-8" });

        const htmlMinifier = require("html-minifier");
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
}

async function compileCssFile(inputFile, outputFile, optimize) {
    const postcss = require("postcss");

    // Make plugins array
    const plugins = [
        require("postcss-import")(),
    ];
    if (optimize) {
        plugins.push(
            require("postcss-preset-env")({ browsers: ["> 0%", "not ie < 8"] }),
            require("cssnano")({ preset: "default" }),
        );
    }

    const original = await fs.promises.readFile(inputFile, { encoding: "utf-8" });
    const result = await postcss(plugins)
        .process(original, {
            from: inputFile,
            to: outputFile,
        });
    await fs.promises.mkdir(path.dirname(outputFile), { recursive: true });
    await fs.promises.writeFile(outputFile, result.css);
}

async function compileCss() {
    console.log("compiling CSS...");

    const baseNames = await getCssFiles();
    return baseNames.map(baseName => {
        const inputFile = path.join(CSS_SRC_DIR, baseName);
        const outputFile = path.join(CSS_OUT_DIR, baseName);
        return compileCssFile(inputFile, outputFile, true);
    });
}

async function minifyJs() {
    console.log("minifying JS...");

    const googleClosureCompiler = require("google-closure-compiler");
    const compiler = new googleClosureCompiler.jsCompiler({
        compilation_level: "ADVANCED",
        env: "BROWSER",
        language_in: "ECMASCRIPT5",
        language_out: "ECMASCRIPT5",
        isolation_mode: "IIFE",
    });
    
    const baseNames = await getJsFiles();
    return baseNames.map(async baseName => {
        const inputFile = path.join(__dirname, "src", "js", baseName);
        const outputFile = path.join(__dirname, "dist", "assets", "js", baseName);

        const original = await fs.promises.readFile(inputFile, { encoding: "utf-8" });
        const minified = await new Promise((resolve, reject) => {
            compiler.run([
                {
                    src: original,
                    path: "src/js/log-in.js",
                }
            ], (exitCode, outputFiles, errors) => {
                if (exitCode !== 0) {
                    reject(new Error("failed to minify JS: " + errors));
                }
                else {
                    resolve(outputFiles[0].src);
                }
            });
        });
        await fs.promises.mkdir(path.dirname(outputFile), { recursive: true });
        await fs.promises.writeFile(outputFile, minified);
    });
}

function build() {
    let promisesOfPromises = [];

    if (argv.html)
        promisesOfPromises.push(minifyHtml());
    if (argv.css)
        promisesOfPromises.push(compileCss());
    if (argv.js)
        promisesOfPromises.push(minifyJs());

    const promises = promisesOfPromises
        .map(promiseOfPromises => promiseOfPromises
            .then(promises => Promise.all(promises)));
    return Promise.all(promises);
}

function callOnChange(file, cb) {
    const watcher = fs.watch(file);

    let delayTimeout = null;
    watcher.on("change", (_eventType, _filename) => {
        // Debounce updates
        if (delayTimeout !== null)
            return;

        delayTimeout = setTimeout(() => {
            cb();
            delayTimeout = null;
        }, 200);
    });
}

async function watch() {
    const filesToCopy = [];

    if (argv.html) {
        for (let baseName of await getTemplateFiles()) {
            filesToCopy.push({
                from: path.join(TEMPLATES_SRC_DIR, baseName),
                to: path.join(TEMPLATES_OUT_DIR, baseName),
            });
        }
    }
    if (argv.css) {
        for (let baseName of await getCssFiles()) {
            const inputFile = path.join(CSS_SRC_DIR, baseName);
            const outputFile = path.join(CSS_OUT_DIR, baseName);

            // Initial compilation
            compileCss(inputFile, outputFile, false);
            // Watch for file changes and recompile
            callOnChange(inputFile, () => compileCss(inputFile, outputFile, false));
        }
    }
    if (argv.js) {
        for (let baseName of await getJsFiles()) {
            filesToCopy.push({
                from: path.join(JS_SRC_DIR, baseName),
                to: path.join(JS_OUT_DIR, baseName),
            });
        }
    }

    function copyAsset(from, to) {
        console.log(`copying asset ${from} to ${to}...`);
        fs.promises.mkdir(path.dirname(to), { recursive: true })
            .then(() => fs.promises.copyFile(from, to))
            .catch(err => console.error("failed to copy asset", err));
    }

    for (let file of filesToCopy) {
        // Initial copy
        copyAsset(file.from, file.to);
        // Watch for file changes
        callOnChange(file.from, () => copyAsset(file.from, file.to));
    }
}

async function main() {
    if (argv.clean) {
        console.log("deleting build directory...");
        
        await fs.promises.rmdir(path.join(__dirname, "dist"), { recursive: true });
    }

    if (argv.watch) {
        await watch();
    } else {
        await build();
    }
}

main().catch(console.error);
