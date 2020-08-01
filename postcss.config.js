module.exports = {
    plugins: [
        require("postcss-cssnext")({ browsers: ["> 0%", "not ie < 8"] }),
        require("cssnano")({ preset: "default" }),
    ],
};
