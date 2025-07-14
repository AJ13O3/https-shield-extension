const path = require('path');

module.exports = {
  entry: {
    background: './extension/src/background.js',
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
  }
};