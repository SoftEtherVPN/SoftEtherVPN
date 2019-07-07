const path = require('path');

module.exports = {
    mode: "development", // "production" | "development" | "none"

    entry: "./src/ts/main.ts",
    devtool: 'inline-source-map',

    output: {
        path: path.join(__dirname, "out_webpack"),
        filename: "bundle.js",
        libraryTarget: 'var',
        library: 'JS'
    },

    module: {
        rules: [{
            test: /\.ts$/,
            loader: "ts-loader",
            options:
            {
                configFile: "tsconfig_webpack.json"
            },
            include: path.join(__dirname, "./src/ts/"),
            exclude: /node_modules/
        }]
    },

    resolve: {
        modules: [
            "node_modules",
        ],
        extensions: [
            ".ts",
            ".js"
        ]
    }
};
