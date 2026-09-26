const native = require('./quad_fast_node.node');

module.exports = {
  version: native.version,
  quadsToIpc: native.quadsToIpc,
  ipcToQuads: native.ipcToQuads,
  quadsToJellyFrames: native.quadsToJellyFrames,
  jellyFramesToQuads: native.jellyFramesToQuads,
};
