module.exports = {
    plugins: [
        require("postcss-preset-env")({ browsers: ["> 0%", "not ie < 8"] }),
        require("cssnano")({ preset: "default" }),
    ],
};
