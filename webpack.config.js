const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = {
  entry: {
    background: './extension/src/background-enhanced.js',
    content: './extension/src/content.js',
    popup: './extension/src/popup.js'
  },
  output: {
    path: path.resolve(__dirname, 'extension/dist'),
    filename: '[name].js'
  },
  resolve: {
    extensions: ['.js']
  },
  mode: 'development',
  devtool: 'inline-source-map',
  watch: false,
  watchOptions: {
    ignored: /node_modules/
  },
  optimization: {
    minimize: false
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { 
          from: 'extension/src/pages',
          to: '../src/pages'
        }
      ]
    })
  ]
};