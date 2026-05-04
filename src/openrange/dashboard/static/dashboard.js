const model = {
  briefing: {
    snapshot_id: null,
    title: "",
    goal: "",
    entrypoints: [],
    missions: [],
  },
  topology: {
    snapshot_id: null,
    world: {},
    tasks: [],
    artifact_paths: [],
    services: [],
    edges: [],
    zones: [],
    users: [],
    green_personas: [],
  },
  lineage: { snapshot_id: null, admission: null, nodes: [] },
  state: {
    running: false,
    status: "waiting_for_snapshot",
    health: { uptime: 100, defense: 100, integrity: 100 },
    events: [],
  },
  actors: [],
  narration: { narration: "No episode activity yet." },
};

const runState = {
  activeRun: null,
  runs: [],
  events: null,
  narration: null,
  followLatest: true,
};

function withRun(path) {
  if (!runState.activeRun) return path;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}run=${encodeURIComponent(runState.activeRun)}`;
}

async function json(path, options) {
  const response = await fetch(withRun(path), options);
  return response.json();
}

function text(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function escapeHtml(value) {
  return text(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function plural(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function pillClass(value) {
  if (value === true) return "pill green";
  if (value === false) return "pill red";
  return "pill amber";
}

function renderInspector() {
  const inspector = document.getElementById("inspector");
  const snapshotId = model.topology.snapshot_id;
  if (!snapshotId) {
    inspector.hidden = true;
    return;
  }
  inspector.hidden = false;
  document.getElementById("snapshot-id").textContent = snapshotId;
  const tasks = model.topology.tasks || [];
  const services = model.topology.services || [];
  const artifacts = model.topology.artifact_paths || [];
  const lineageNodes = model.lineage.nodes || [];
  document.getElementById("identity-stats").innerHTML = [
    stat(tasks.length, plural(tasks.length, "task")),
    stat(services.length, plural(services.length, "service")),
    stat(artifacts.length, plural(artifacts.length, "artifact")),
    stat(lineageNodes.length, plural(lineageNodes.length, "lineage step")),
  ].join("");
}

function stat(value, label) {
  return `<div class="stat"><strong>${escapeHtml(value)}</strong>` +
    `<span>${escapeHtml(label)}</span></div>`;
}

const sim = {
  initialized: false,
  fallback: false,
  fingerprint: "",
  seenEvents: new Set(),
  scene: null,
  camera: null,
  renderer: null,
  controls: null,
  worldGroup: null,
  clock: null,
  servicePositions: {},
  deskPositions: [],
  characters: {},
  effects: [],
  pendingReplies: [],
  selectedActorId: "",
};

function shortText(value, max = 80) {
  const rendered = text(value);
  if (rendered.length <= max) return rendered;
  return `${rendered.slice(0, Math.max(0, max - 3))}...`;
}

function eventData(event) {
  return event.data && typeof event.data === "object" ? event.data : {};
}

function simulationRole(value) {
  const kind = typeof value === "string"
    ? value
    : eventData(value).actor_kind || value.actor || "event";
  if (kind === "agent" || kind === "red") return "agent";
  if (kind === "npc" || kind === "green") return "npc";
  if (kind === "system" || kind === "blue") return "system";
  return "event";
}

function roleColor(role) {
  if (role === "agent") return 0xfb7185;
  if (role === "npc") return 0x4ade80;
  if (role === "system") return 0x38bdf8;
  return 0xfacc15;
}

function roleCss(role) {
  return role === "agent" || role === "npc" || role === "system" ? role : "";
}

function eventLabel(event) {
  const data = eventData(event);
  const action = data.action ? ` ${shortText(data.action, 54)}` : "";
  const observation = data.observation ? ` -> ${shortText(data.observation, 44)}` : "";
  return `${event.actor} -> ${event.target}: ${event.type}${action}${observation}`;
}

function stationDefinitions() {
  const byId = new Map();
  const add = (id, label, kind, zone = "") => {
    if (!id || byId.has(id)) return;
    byId.set(id, {
      id,
      label: shortText(label || id, 18),
      kind: kind || "service",
      zone,
    });
  };

  (model.topology.services || []).forEach((service) => {
    add(
      service.id,
      service.id || service.kind,
      service.kind || service.role || "service",
      service.zone || "",
    );
  });
  (model.briefing.entrypoints || []).forEach((entry) => {
    add(entry.target, entry.target, entry.kind, "episode");
  });
  (model.topology.tasks || []).forEach((task) => {
    const entrypoints = task.entrypoints || [];
    if (!entrypoints.length) add(task.id, task.id, "task", "episode");
    entrypoints.forEach((entry) => (
      add(entry.target, entry.target, entry.kind, "episode")
    ));
  });
  if (!byId.size && model.topology.snapshot_id) {
    add("world", model.briefing.title || "world", "world", "episode");
  }
  return Array.from(byId.values()).slice(0, 12);
}

function actorDefinitions() {
  const byId = new Map();
  const add = (id, role) => {
    if (id && !byId.has(id)) byId.set(id, simulationRole(role));
  };
  (model.actors || []).forEach((actor) => {
    add(actor.actor_id, actor.actor_kind);
  });
  (model.state.events || []).forEach((event) => {
    const data = eventData(event);
    add(data.actor_id || event.actor, event);
  });
  (model.topology.services || []).forEach((service) => {
    if (service.role === "red") add("red", "agent");
    if (service.role === "blue") add("blue", "system");
  });
  const people = (model.topology.green_personas || []).length
    ? model.topology.green_personas
    : model.topology.users || [];
  people.forEach((persona) => {
    add(persona.id || persona.email, "npc");
  });
  if (!byId.size && model.topology.snapshot_id) {
    add("agent", "agent");
    add("system", "system");
  }
  return Array.from(byId.entries()).map(([id, role]) => ({ id, role }));
}

function simulationFingerprint() {
  // Fingerprint stability matters: any change here triggers a full
  // world rebuild that disposes characters mid-walk. Limit it to
  // *topology-derived* identity (stations + personas declared by
  // the snapshot) — event-derived actors (chatters firing speech)
  // are added incrementally by ``applySimulationEvent`` and don't
  // need to bounce the scene.
  const stationIds = stationDefinitions().map((station) => station.id).join("|");
  const personas = (model.topology.green_personas || []).length
    ? model.topology.green_personas
    : model.topology.users || [];
  const personaIds = personas
    .map((persona) => persona.id || persona.email || "")
    .filter(Boolean)
    .join("|");
  return `${model.topology.snapshot_id || "empty"}:${stationIds}:${personaIds}`;
}

function initSimulation() {
  if (sim.initialized) return;
  sim.initialized = true;
  const canvas = document.getElementById("sim-canvas");
  if (!canvas || !window.THREE) {
    sim.fallback = true;
    drawFallbackSimulation();
    return;
  }

  sim.scene = new THREE.Scene();
  sim.scene.background = new THREE.Color(0x07111f);
  sim.scene.fog = new THREE.FogExp2(0x07111f, 0.018);
  sim.clock = new THREE.Clock();

  sim.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
  sim.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  sim.renderer.shadowMap.enabled = true;
  sim.renderer.shadowMap.type = THREE.PCFSoftShadowMap;

  sim.camera = new THREE.OrthographicCamera(-16, 16, 12, -12, 0.1, 200);
  sim.camera.position.set(26, 24, 26);
  sim.camera.lookAt(0, 0, 0);

  if (THREE.OrbitControls) {
    sim.controls = new THREE.OrbitControls(sim.camera, canvas);
    sim.controls.enableDamping = true;
    sim.controls.dampingFactor = 0.06;
    sim.controls.maxPolarAngle = Math.PI / 2.15;
    sim.controls.minPolarAngle = Math.PI / 6;
  }

  sim.scene.add(new THREE.AmbientLight(0xffffff, 0.56));
  const keyLight = new THREE.DirectionalLight(0xfff5e6, 1.25);
  keyLight.position.set(18, 32, 22);
  keyLight.castShadow = true;
  keyLight.shadow.mapSize.width = 2048;
  keyLight.shadow.mapSize.height = 2048;
  keyLight.shadow.camera.left = -28;
  keyLight.shadow.camera.right = 28;
  keyLight.shadow.camera.top = 28;
  keyLight.shadow.camera.bottom = -28;
  sim.scene.add(keyLight);

  addBaseSimulationScene();
  resizeSimulation();
  window.addEventListener("resize", resizeSimulation);
  installActorSelection(canvas);
  animateSimulation();
}

function addBaseSimulationScene() {
  const gridCanvas = document.createElement("canvas");
  const ctx = gridCanvas.getContext("2d");
  gridCanvas.width = 128;
  gridCanvas.height = 128;
  ctx.fillStyle = "#d8d2ca";
  ctx.fillRect(0, 0, 128, 128);
  ctx.strokeStyle = "#b9aa9b";
  ctx.lineWidth = 2;
  for (let step = 0; step <= 128; step += 16) {
    ctx.beginPath();
    ctx.moveTo(0, step);
    ctx.lineTo(128, step);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(step, 0);
    ctx.lineTo(step, 128);
    ctx.stroke();
  }
  const texture = new THREE.CanvasTexture(gridCanvas);
  texture.wrapS = THREE.RepeatWrapping;
  texture.wrapT = THREE.RepeatWrapping;
  texture.repeat.set(28, 28);
  const floor = new THREE.Mesh(
    new THREE.PlaneGeometry(54, 54),
    new THREE.MeshStandardMaterial({ map: texture, roughness: 0.72 }),
  );
  floor.rotation.x = -Math.PI / 2;
  floor.receiveShadow = true;
  sim.scene.add(floor);

  const wallMaterial = new THREE.MeshStandardMaterial({ color: 0xe2e8f0 });
  [
    { size: [32, 2.8, .45], pos: [0, 1.4, -16] },
    { size: [.45, 2.8, 32], pos: [-16, 1.4, 0] },
  ].forEach((wall) => {
    const mesh = new THREE.Mesh(new THREE.BoxGeometry(...wall.size), wallMaterial);
    mesh.position.set(...wall.pos);
    mesh.castShadow = true;
    sim.scene.add(mesh);
  });

  sim.worldGroup = new THREE.Group();
  sim.scene.add(sim.worldGroup);
}

function clearSimulationWorld() {
  if (!sim.worldGroup) return;
  while (sim.worldGroup.children.length) {
    const child = sim.worldGroup.children[0];
    disposeObject(child);
    sim.worldGroup.remove(child);
  }
  sim.servicePositions = {};
  sim.deskPositions = [];
  sim.characters = {};
  sim.effects = [];
}

// Office-staff desks. Independent of cyber services — services are
// the agent's attack surface; desks are where the chatter NPCs live
// their day. Two rows of four desks running along the south side of
// the floor, away from the service rack on the north/center.
const DESK_GRID_OFFSETS = [
  [-9, 8], [-3, 8], [3, 8], [9, 8],
  [-9, 13], [-3, 13], [3, 13], [9, 13],
];

function addOfficeDesks() {
  DESK_GRID_OFFSETS.forEach(([x, z], index) => {
    const station = {
      id: `desk-${index}`,
      label: "", // unlabeled — desks are scenery, not nav targets
      kind: "desk",
      zone: "office",
    };
    addStation(station, x, z, index + 100); // offset accent palette so desks look uniform
    sim.deskPositions.push(sim.servicePositions[station.id]);
  });
}

function homeDeskFor(actorId) {
  // Stable per-name hash → desk index. Same name always maps to the
  // same desk so a re-run of the eval re-plays the same seating.
  if (!sim.deskPositions.length) return null;
  let hash = 0;
  for (let i = 0; i < actorId.length; i += 1) {
    hash = (hash * 31 + actorId.charCodeAt(i)) >>> 0;
  }
  return sim.deskPositions[hash % sim.deskPositions.length];
}

function disposeObject(object) {
  object.traverse((child) => {
    if (child.geometry) child.geometry.dispose();
    if (child.material) {
      const materials = Array.isArray(child.material)
        ? child.material
        : [child.material];
      materials.forEach((material) => {
        if (material.map) material.map.dispose();
        material.dispose();
      });
    }
  });
}

function rebuildSimulationWorld() {
  if (sim.fallback) return;
  const nextFingerprint = simulationFingerprint();
  if (sim.fingerprint === nextFingerprint) return;
  sim.fingerprint = nextFingerprint;
  clearSimulationWorld();

  const stations = stationDefinitions();
  stations.forEach((station, index) => {
    const pos = stationPosition(station, index, stations);
    addStation(station, pos.x, pos.z, index);
  });

  // Office desks live independently of the cyber services. NPCs sit
  // at desks; the agent attacks services. Render desks last so their
  // accent rings sit on top of the floor grid.
  addOfficeDesks();

  actorDefinitions().forEach((actor) => {
    // Only NPCs get rendered as people. The agent (red) and runtime
    // (blue) actors live in the request log + service ring flashes —
    // they are not bodies in the office. Keeping them out keeps the
    // floor a clean office scene.
    if (actor.role !== "npc") return;
    const home = homeDeskFor(actor.id);
    if (home) {
      addCharacter(actor.id, actor.role, home.x, home.z + 1.0);
      sim.characters[actor.id].homeDesk = home;
    }
  });
}

function stationPosition(station, index, stations) {
  const fixed = {
    "sandbox-red": [-18, -13],
    "red": [-18, -13],
    "svc-web": [-7, -8],
    "svc-email": [6, -8],
    "svc-fileshare": [-10, -2],
    "svc-db": [1, 1],
    "svc-idp": [-6, 7],
    "svc-siem": [8, 6],
    "sandbox-blue": [15, 10],
    "blue": [15, 10],
  };
  if (fixed[station.id]) {
    return { x: fixed[station.id][0], z: fixed[station.id][1] };
  }

  const zoneRows = {
    external: -13,
    dmz: -8,
    corp: -3,
    data: 2,
    management: 7,
    episode: 11,
    artifact: 14,
  };
  if (station.zone && zoneRows[station.zone] !== undefined) {
    const zoneStations = stations.filter((item) => item.zone === station.zone);
    const zoneIndex = zoneStations.findIndex((item) => item.id === station.id);
    const count = Math.max(1, zoneStations.length);
    return {
      x: (zoneIndex - (count - 1) / 2) * 6,
      z: zoneRows[station.zone],
    };
  }

  const total = stations.length;
  const columns = Math.max(2, Math.ceil(Math.sqrt(Math.max(total, 1))));
  const row = Math.floor(index / columns);
  const column = index % columns;
  return {
    x: (column - (columns - 1) / 2) * 7.2,
    z: (row - 1) * 5.4,
  };
}

function addStation(station, x, z, index) {
  const colors = [0x38bdf8, 0xa78bfa, 0xfacc15, 0x4ade80, 0xfb7185, 0x22d3ee];
  const accent = colors[index % colors.length];
  const group = new THREE.Group();
  group.position.set(x, 0, z);

  const deskMaterial = new THREE.MeshStandardMaterial({ color: 0x94a3b8 });
  const screenMaterial = new THREE.MeshStandardMaterial({
    color: 0x08111f,
    emissive: accent,
    emissiveIntensity: .18,
  });
  const top = new THREE.Mesh(new THREE.BoxGeometry(2.4, .12, 1.15), deskMaterial);
  top.position.y = .78;
  top.castShadow = true;
  group.add(top);

  [-.8, .8].forEach((legX) => {
    [-.36, .36].forEach((legZ) => {
      const leg = new THREE.Mesh(new THREE.BoxGeometry(.12, .78, .12), deskMaterial);
      leg.position.set(legX, .38, legZ);
      leg.castShadow = true;
      group.add(leg);
    });
  });

  const monitor = new THREE.Mesh(new THREE.BoxGeometry(.88, .58, .08), screenMaterial);
  monitor.position.set(0, 1.16, -.38);
  monitor.castShadow = true;
  group.add(monitor);

  const ring = new THREE.Mesh(
    new THREE.RingGeometry(1.45, 1.58, 40),
    new THREE.MeshBasicMaterial({
      color: accent,
      transparent: true,
      opacity: .45,
      side: THREE.DoubleSide,
    }),
  );
  ring.rotation.x = -Math.PI / 2;
  ring.position.y = .04;
  group.add(ring);

  // Stations (services + desks) render unlabeled. The office is
  // visual scenery; if a viewer needs to know which station is what,
  // they'll click on the actor or read the live event feed.

  sim.worldGroup.add(group);
  sim.servicePositions[station.id] = { x, z, ring, accent };
}

function addCharacter(id, role, x, z) {
  const group = new THREE.Group();
  group.position.set(x, 0, z);
  const color = roleColor(role);
  const shirt = new THREE.MeshStandardMaterial({ color });
  const dark = new THREE.MeshStandardMaterial({ color: 0x1e293b });
  const skin = new THREE.MeshStandardMaterial({ color: 0xffd9ad });

  const body = new THREE.Mesh(new THREE.BoxGeometry(.48, .62, .28), shirt);
  body.position.y = .92;
  body.castShadow = true;
  group.add(body);

  const head = new THREE.Mesh(new THREE.BoxGeometry(.32, .32, .32), skin);
  head.position.y = 1.42;
  head.castShadow = true;
  group.add(head);

  const legs = [];
  [-.14, .14].forEach((legX) => {
    const leg = new THREE.Mesh(new THREE.BoxGeometry(.16, .58, .18), dark);
    leg.position.set(legX, .42, 0);
    leg.castShadow = true;
    legs.push(leg);
    group.add(leg);
  });

  const indicator = new THREE.Mesh(
    new THREE.OctahedronGeometry(.2, 0),
    new THREE.MeshStandardMaterial({
      color,
      emissive: color,
      emissiveIntensity: .72,
    }),
  );
  indicator.scale.y = 2.4;
  indicator.position.y = 2.08;
  group.add(indicator);

  const label = makeLabelSprite(shortText(id, 16), "#ffffff", "rgba(15, 23, 42, .78)");
  label.position.y = 2.72;
  group.add(label);

  group.userData.actorId = id;
  group.traverse((child) => { child.userData.actorId = id; });
  sim.worldGroup.add(group);
  sim.characters[id] = {
    group,
    role,
    legs,
    indicator,
    target: null,
    phase: Math.random() * 4,
    homeDesk: null,
    returnHomeAt: null,
  };
}

function makeLabelSprite(label, color, background) {
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  canvas.width = 384;
  canvas.height = 82;
  ctx.fillStyle = background;
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = "rgba(255,255,255,.18)";
  ctx.lineWidth = 3;
  ctx.strokeRect(1.5, 1.5, canvas.width - 3, canvas.height - 3);
  ctx.font = "800 28px Nunito, system-ui, sans-serif";
  ctx.fillStyle = color;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(label, canvas.width / 2, canvas.height / 2);
  const texture = new THREE.CanvasTexture(canvas);
  texture.minFilter = THREE.LinearFilter;
  const material = new THREE.SpriteMaterial({
    map: texture,
    transparent: true,
    depthTest: false,
  });
  const sprite = new THREE.Sprite(material);
  sprite.scale.set(3.8, .82, 1);
  return sprite;
}

function updateSimulationFromEvents() {
  if (sim.fallback) {
    drawFallbackSimulation();
    return;
  }
  (model.state.events || []).forEach((event) => {
    if (sim.seenEvents.has(event.id)) return;
    sim.seenEvents.add(event.id);
    applySimulationEvent(event);
  });
}

function applySimulationEvent(event) {
  const role = simulationRole(event);
  const data = eventData(event);
  const actorId = data.actor_id || event.actor || role;
  const action = (data.action && typeof data.action === "object") ? data.action : {};

  // Non-NPC events (agent HTTP traffic, system/runtime events) don't
  // render as bodies in the office. Flash the target service's ring
  // so the viewer sees activity on the rack, and that's it — no
  // walking figure crashing the office scene.
  if (role !== "npc") {
    const target = sim.servicePositions[event.target]
      || sim.servicePositions[data.target];
    if (target?.ring) {
      target.ring.material.color.setHex(roleColor(role));
    }
    return;
  }

  if (!sim.characters[actorId]) {
    const home = homeDeskFor(actorId);
    if (home) {
      addCharacter(actorId, role, home.x, home.z + 1.0);
      sim.characters[actorId].homeDesk = home;
    } else {
      addCharacter(actorId, role, 18, 10);
    }
  }
  const character = sim.characters[actorId];
  if (!character) return;

  // Presence events spawn the character (handled above) and do
  // nothing else — no bubble, no walk. Lets chatters show up at
  // their desks the instant their NPC.start fires, before any
  // cadence-driven action.
  if (action.present) return;

  // Speech events: pop a fading bubble over the character and stop —
  // don't yank them across the floor toward an unrelated target.
  if (typeof action.speak === "string" && action.speak.length > 0) {
    spawnSpeechBubble(character, action.speak);
    return;
  }

  // "move" event: walk to a colleague's desk for a chat, then return
  // home a longer beat later. Desks only — services are off limits,
  // the agent owns those. While the visitor is at the host's desk,
  // schedule a brief reply bubble from the host so the exchange
  // reads as a real two-way conversation rather than one NPC
  // talking at a desk.
  if (character.homeDesk && action.move) {
    const targetDesk = pickColleagueDesk(character.homeDesk);
    if (!targetDesk) return;
    character.target = neighborOffset(targetDesk, actorId);
    const now = sim.clock?.getElapsedTime() || 0;
    // Tight visit: walks at 8 units/s land within 1-2s, brief chat,
    // then walk back. Total round-trip ~6-8s so multiple visits
    // overlap across the floor without each one feeling slow.
    character.returnHomeAt = now + 4 + Math.random() * 2;
    scheduleColleagueReply(targetDesk, now + 1.5 + Math.random() * 1);
  }
}

const _COLLEAGUE_REPLIES = [
  "yeah", "totally", "huh", "right", "no way", "fair", "got it",
  "okay", "hmm", "sure", "later", "noted",
];

function scheduleColleagueReply(targetDesk, atTime) {
  // Find which NPC lives at the target desk and queue a one-line
  // reply on the animation timeline. Cheap timer — checks each
  // tick against ``sim.clock.getElapsedTime()``.
  const host = Object.values(sim.characters).find(
    (character) => character.homeDesk === targetDesk,
  );
  if (!host) return;
  const reply = _COLLEAGUE_REPLIES[
    Math.floor(Math.random() * _COLLEAGUE_REPLIES.length)
  ];
  if (!sim.pendingReplies) sim.pendingReplies = [];
  sim.pendingReplies.push({ host, reply, atTime });
}

function pickColleagueDesk(homeDesk) {
  const others = sim.deskPositions.filter((desk) => desk !== homeDesk);
  if (!others.length) return null;
  return others[Math.floor(Math.random() * others.length)];
}

function neighborOffset(target, actorId) {
  const offset = actorId.split("").reduce((sum, char) => sum + char.charCodeAt(0), 0);
  const angle = (offset % 8) * Math.PI / 4;
  return {
    x: target.x + Math.cos(angle) * 1.5,
    z: target.z + Math.sin(angle) * 1.5,
  };
}

function spawnSpeechBubble(character, text) {
  // One bubble per character at a time — replace any prior one so a
  // fast-talking NPC doesn't stack five bubbles vertically.
  if (character.bubble) {
    character.group.remove(character.bubble);
    disposeObject(character.bubble);
    character.bubble = null;
  }
  const sprite = makeBubbleSprite(shortText(text, 56));
  sprite.position.set(0, 3.05, 0);
  character.group.add(sprite);
  character.bubble = sprite;
  character.bubbleLife = 4.0;
}

function makeBubbleSprite(text) {
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  canvas.width = 512;
  canvas.height = 128;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  // Rounded-rect bubble.
  const radius = 28;
  const padding = 18;
  const x = padding;
  const y = padding;
  const w = canvas.width - padding * 2;
  const h = canvas.height - padding * 2 - 14;
  ctx.fillStyle = "rgba(255, 255, 255, .94)";
  ctx.strokeStyle = "rgba(15, 23, 42, .85)";
  ctx.lineWidth = 4;
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.lineTo(x + w - radius, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + radius);
  ctx.lineTo(x + w, y + h - radius);
  ctx.quadraticCurveTo(x + w, y + h, x + w - radius, y + h);
  // Tail.
  ctx.lineTo(canvas.width / 2 + 16, y + h);
  ctx.lineTo(canvas.width / 2, y + h + 18);
  ctx.lineTo(canvas.width / 2 - 16, y + h);
  ctx.lineTo(x + radius, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - radius);
  ctx.lineTo(x, y + radius);
  ctx.quadraticCurveTo(x, y, x + radius, y);
  ctx.closePath();
  ctx.fill();
  ctx.stroke();
  ctx.fillStyle = "#0f172a";
  ctx.font = "700 30px Nunito, system-ui, sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(text, canvas.width / 2, padding + h / 2 - 4);
  const texture = new THREE.CanvasTexture(canvas);
  texture.minFilter = THREE.LinearFilter;
  const material = new THREE.SpriteMaterial({
    map: texture,
    transparent: true,
    depthTest: false,
  });
  const sprite = new THREE.Sprite(material);
  sprite.scale.set(4.4, 1.1, 1);
  return sprite;
}

function spawnPulse(from, to, role) {
  const color = roleColor(role);
  const points = [
    new THREE.Vector3(from.x, 1.25, from.z),
    new THREE.Vector3(to.x, 1.25, to.z),
  ];
  const line = new THREE.Line(
    new THREE.BufferGeometry().setFromPoints(points),
    new THREE.LineBasicMaterial({ color, transparent: true, opacity: .88 }),
  );
  sim.worldGroup.add(line);
  sim.effects.push({ object: line, life: 1.2 });

  for (let index = 0; index < 8; index += 1) {
    const particle = new THREE.Mesh(
      new THREE.BoxGeometry(.12, .12, .12),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 1 }),
    );
    particle.position.set(to.x, 1.1, to.z);
    sim.worldGroup.add(particle);
    sim.effects.push({
      object: particle,
      life: .9,
      velocity: new THREE.Vector3(
        (Math.random() - .5) * .18,
        Math.random() * .16 + .06,
        (Math.random() - .5) * .18,
      ),
    });
  }
}

function animateSimulation() {
  if (!sim.renderer || !sim.scene || !sim.camera || !sim.clock) return;
  requestAnimationFrame(animateSimulation);
  const dt = Math.min(sim.clock.getDelta(), 0.1);
  const elapsed = sim.clock.getElapsedTime();

  Object.values(sim.characters).forEach((character) => {
    character.indicator.rotation.y += dt * 3.2;
    character.indicator.position.y = 2.08 + Math.sin(elapsed * 3) * .05;
    character.phase += dt * 7;
    if (character.bubble) {
      character.bubbleLife -= dt;
      const life = character.bubbleLife;
      if (life <= 0) {
        character.group.remove(character.bubble);
        disposeObject(character.bubble);
        character.bubble = null;
      } else if (character.bubble.material) {
        // Hold full opacity for the first ~3s then fade over the last 1s.
        const opacity = life > 1 ? 1 : Math.max(0, life);
        character.bubble.material.opacity = opacity;
      }
    }
    if (character.target) {
      const pos = character.group.position;
      const dx = character.target.x - pos.x;
      const dz = character.target.z - pos.z;
      const distance = Math.sqrt(dx * dx + dz * dz);
      if (distance > .24) {
        // Sped-up walking — 8 units/s feels right for a "scurry across
        // the office to chat" demo where chatter cadence is also fast.
        pos.x += (dx / distance) * dt * 8.0;
        pos.z += (dz / distance) * dt * 8.0;
        character.group.rotation.y = Math.atan2(dx, dz);
        // Legs swing faster too (phase already advances at dt*7).
        character.legs.forEach((leg, index) => {
          leg.rotation.x = Math.sin(character.phase + index * Math.PI) * .65;
        });
      } else {
        character.target = null;
        character.legs.forEach((leg) => { leg.rotation.x = 0; });
      }
    } else if (
      character.role === "npc"
      && character.homeDesk
      && character.returnHomeAt != null
      && elapsed >= character.returnHomeAt
    ) {
      // Drift back to the home desk after the colleague visit. No
      // random wandering — chatters either sit at their desk or are
      // visiting a specific colleague.
      character.target = neighborOffset(character.homeDesk, character.group.userData.actorId || "");
      character.returnHomeAt = null;
    }
  });

  if (sim.pendingReplies && sim.pendingReplies.length) {
    sim.pendingReplies = sim.pendingReplies.filter((reply) => {
      if (elapsed < reply.atTime) return true;
      if (sim.characters[reply.host.group?.userData?.actorId] === reply.host
          || Object.values(sim.characters).includes(reply.host)) {
        spawnSpeechBubble(reply.host, reply.reply);
      }
      return false;
    });
  }

  for (let index = sim.effects.length - 1; index >= 0; index -= 1) {
    const effect = sim.effects[index];
    effect.life -= dt;
    if (effect.velocity) {
      effect.object.position.add(effect.velocity);
      effect.velocity.y -= .01;
    }
    if (effect.object.material) {
      effect.object.material.opacity = Math.max(0, effect.life);
    }
    if (effect.life <= 0) {
      sim.worldGroup.remove(effect.object);
      disposeObject(effect.object);
      sim.effects.splice(index, 1);
    }
  }

  if (sim.controls) sim.controls.update();
  sim.renderer.render(sim.scene, sim.camera);
}

function resizeSimulation() {
  const canvas = document.getElementById("sim-canvas");
  if (!canvas) return;
  const width = canvas.clientWidth || window.innerWidth;
  const height = canvas.clientHeight || window.innerHeight;
  if (sim.renderer && sim.camera) {
    const aspect = width / Math.max(1, height);
    const frustum = 16;
    sim.camera.left = -frustum * aspect;
    sim.camera.right = frustum * aspect;
    sim.camera.top = frustum;
    sim.camera.bottom = -frustum;
    sim.camera.updateProjectionMatrix();
    sim.renderer.setSize(width, height, false);
  }
  if (sim.fallback) drawFallbackSimulation();
}

function installActorSelection(canvas) {
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  canvas.addEventListener("click", (event) => {
    if (!sim.camera) return;
    const bounds = canvas.getBoundingClientRect();
    pointer.x = ((event.clientX - bounds.left) / Math.max(1, bounds.width)) * 2 - 1;
    pointer.y = -(((event.clientY - bounds.top) / Math.max(1, bounds.height)) * 2 - 1);
    raycaster.setFromCamera(pointer, sim.camera);
    const roots = Object.values(sim.characters).map((character) => character.group);
    const hits = raycaster.intersectObjects(roots, true);
    for (const hit of hits) {
      const actorId = hit.object.userData.actorId;
      if (actorId) {
        showActorDetails(actorId);
        return;
      }
    }
  });

  document.getElementById("sim-actor-close").addEventListener("click", () => {
    sim.selectedActorId = "";
    renderSelectedActor();
  });
}

function drawFallbackSimulation() {
  const canvas = document.getElementById("sim-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.clientWidth || window.innerWidth;
  const height = canvas.clientHeight || window.innerHeight;
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
  }
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#07111f";
  ctx.fillRect(0, 0, width, height);
  ctx.strokeStyle = "rgba(147,197,253,.18)";
  for (let x = -height; x < width + height; x += 42) {
    ctx.beginPath();
    ctx.moveTo(x, height * .78);
    ctx.lineTo(x + height, 0);
    ctx.stroke();
  }
  const stations = stationDefinitions();
  const centerX = width / 2;
  const centerY = height / 2 + 30;
  stations.forEach((station, index) => {
    const pos = stationPosition(station, index, stations);
    const x = centerX + pos.x * 22;
    const y = centerY + pos.z * 16;
    ctx.fillStyle = "#102a56";
    ctx.strokeStyle = "#8ec5ff";
    ctx.lineWidth = 3;
    ctx.fillRect(x - 56, y - 28, 112, 56);
    ctx.strokeRect(x - 56, y - 28, 112, 56);
    ctx.fillStyle = "#dbeafe";
    ctx.font = "800 12px Nunito, system-ui, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(station.label.toUpperCase(), x, y + 4);
  });
}

function renderSimulationEventLog() {
  const log = document.getElementById("sim-event-log");
  const events = (model.state.events || []).slice(-40).reverse();
  log.innerHTML = "";
  events.forEach((event) => {
    const role = simulationRole(event);
    const item = document.createElement("li");
    const dot = document.createElement("span");
    const label = document.createElement("span");
    dot.className = `sim-dot ${roleCss(role)}`;
    label.textContent = eventLabel(event);
    item.append(dot, label);
    log.appendChild(item);
  });
  if (!events.length) {
    const item = document.createElement("li");
    const dot = document.createElement("span");
    const label = document.createElement("span");
    dot.className = "sim-dot";
    label.textContent = "Waiting for episode events.";
    item.append(dot, label);
    log.appendChild(item);
  }
}

function setGauge(id, value) {
  const gauge = document.getElementById(id);
  const percent = Math.max(0, Math.min(100, value));
  gauge.style.width = `${percent}%`;
  gauge.style.backgroundColor = percent > 66
    ? "#4ade80"
    : percent > 33 ? "#facc15" : "#fb7185";
}

function actorSummary(actorId) {
  return (model.actors || []).find((actor) => actor.actor_id === actorId) || null;
}

function actorProfile(actorId) {
  const people = (model.topology.green_personas || []).length
    ? model.topology.green_personas
    : model.topology.users || [];
  return people.find((person) => person.id === actorId || person.email === actorId)
    || null;
}

function latestActorEvent(actorId) {
  const events = model.state.events || [];
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    const data = eventData(event);
    if (event.actor === actorId || data.actor_id === actorId) return event;
  }
  return null;
}

function showActorDetails(actorId) {
  sim.selectedActorId = actorId;
  renderSelectedActor();
}

function renderSelectedActor() {
  const panel = document.getElementById("sim-actor-panel");
  const actorId = sim.selectedActorId;
  if (!actorId) {
    panel.classList.remove("visible");
    return;
  }

  const summary = actorSummary(actorId);
  const profile = actorProfile(actorId);
  const latest = latestActorEvent(actorId);
  const role = profile
    ? [profile.role, profile.department].filter(Boolean).join(" / ")
    : summary ? summary.actor_kind : sim.characters[actorId]?.role || "event";
  document.getElementById("sim-actor-name").textContent = actorId;
  document.getElementById("sim-actor-role").textContent = role || "event";
  document.getElementById("sim-actor-kind").textContent =
    summary?.actor_kind || sim.characters[actorId]?.role || "event";
  document.getElementById("sim-actor-events").textContent =
    String(summary?.event_count || 0);
  document.getElementById("sim-actor-targets").textContent =
    (summary?.targets || []).join(", ") || profile?.home_host || "none";
  document.getElementById("sim-actor-latest").textContent =
    latest ? eventLabel(latest) : profile?.awareness || "No activity yet.";

  const history = summary?.history || [];
  const list = document.getElementById("sim-actor-history");
  list.innerHTML = "";
  if (!history.length) {
    const item = document.createElement("li");
    item.textContent = "No recent events.";
    list.appendChild(item);
  } else {
    history.slice().reverse().forEach((entry) => {
      const item = document.createElement("li");
      item.textContent = `${entry.event_type} -> ${entry.target}: ${
        shortText(entry.action || entry.observation || "", 80)
      }`;
      list.appendChild(item);
    });
  }
  panel.classList.add("visible");
}

function renderSimulationChrome() {
  const status = model.state.status || "waiting_for_snapshot";
  const eventCount = model.state.event_count || (model.state.events || []).length;
  const taskCount = (model.topology.tasks || []).length;
  const hasSnapshot = Boolean(model.topology.snapshot_id);
  const health = model.state.health || {};
  document.getElementById("sim-subtitle").textContent = hasSnapshot
    ? `${model.briefing.title || "Admitted world"} - ${plural(taskCount, "task")}`
    : "Waiting for an admitted snapshot";
  document.getElementById("sim-status").textContent = status.replaceAll("_", " ");
  document.getElementById("sim-clock").textContent =
    String(eventCount).padStart(2, "0");
  document.getElementById("sim-narrator").textContent =
    model.narration.narration || "No episode activity yet.";
  document.getElementById("sim-empty").classList.toggle("hidden", hasSnapshot);
  setGauge("sim-uptime-gauge", health.uptime ?? (hasSnapshot ? 100 : 12));
  setGauge("sim-defense-gauge", health.defense ?? 100);
  setGauge("sim-integrity-gauge", health.integrity ?? 100);
  renderSimulationEventLog();
  renderSelectedActor();
}

function renderSimulation() {
  initSimulation();
  renderSimulationChrome();
  if (!sim.fallback) {
    rebuildSimulationWorld();
    updateSimulationFromEvents();
  } else {
    drawFallbackSimulation();
  }
}

function renderBriefing() {
  const briefing = model.briefing;
  const hero = document.getElementById("briefing-hero");
  if (!briefing.snapshot_id) {
    hero.innerHTML = "";
    return;
  }
  const seen = new Set();
  const entrypoints = (briefing.entrypoints || []).filter((entry) => {
    const key = `${entry.kind}:${entry.target}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const entrypointHtml = entrypoints.length
    ? `<p class="briefing-entrypoints">${entrypoints.map((entry) => (
        `<span class="entrypoint">${escapeHtml(entry.kind)}` +
        `<code>${escapeHtml(entry.target)}</code></span>`
      )).join("")}</p>`
    : "";
  hero.innerHTML = `
    <h2>${escapeHtml(briefing.title || "Untitled world")}</h2>
    <p class="briefing-goal">${escapeHtml(briefing.goal || "")}</p>
    ${entrypointHtml}`;
}

function renderTasks() {
  const tasks = model.topology.tasks || [];
  document.getElementById("task-count").textContent = plural(tasks.length, "task");
  document.getElementById("tasks").innerHTML = tasks.length ? tasks.map((task) => {
    const entrypoints = (task.entrypoints || []).map((entry) => (
      `${entry.kind}:${entry.target}`
    )).join(" · ");
    return `<div class="task">
      <h3 class="task-id">${escapeHtml(task.id)}</h3>
      <p class="task-instruction">${escapeHtml(task.instruction)}</p>
      <div class="task-meta">
        <span class="verifier">${escapeHtml(task.verifier_id || "no verifier")}</span>
        ${entrypoints ? `<span>${escapeHtml(entrypoints)}</span>` : ""}
      </div>
    </div>`;
  }).join("") : emptyCard("No tasks generated.");
}

function renderAdmission() {
  const admission = model.lineage.admission;
  const pill = document.getElementById("admission-pill");
  const count = document.getElementById("admission-count");
  if (!admission) {
    pill.className = "pill amber";
    pill.textContent = "Waiting";
    count.textContent = "0 / 0";
    document.getElementById("admission").innerHTML =
      emptyCard("No admission report yet.");
    return;
  }
  pill.className = pillClass(admission.passed);
  pill.textContent = admission.passed ? "Passed" : "Failed";
  const results = Object.entries(admission.verifier_results || {});
  const passed = results.filter(([, result]) => result.passed).length;
  count.textContent = `${passed} / ${results.length}`;
  document.getElementById("admission").innerHTML = results.length
    ? results.map(([taskId, result]) => {
        const cls = result.passed ? "green" : "red";
        const score = result.score != null
          ? Number(result.score).toFixed(2)
          : "—";
        const details = result.details
          ? `<p class="vdetails">${escapeHtml(result.details)}</p>`
          : "";
        return `<div class="verifier-row">
          <span class="vname">${escapeHtml(taskId)}</span>
          <span class="pill ${cls}">${result.passed ? "pass" : "fail"}</span>
          <span class="vscore">${escapeHtml(score)}</span>
          ${details}
        </div>`;
      }).join("")
    : emptyCard("No verifier results.");
}

function renderWorld() {
  const services = model.topology.services || [];
  const zones = model.topology.zones || [];
  document.getElementById("world-count").textContent =
    plural(services.length, "service");
  if (!services.length) {
    document.getElementById("world").innerHTML = emptyCard("No services in topology.");
    return;
  }
  const orderedZones = zones.length
    ? zones
    : Array.from(new Set(services.map((service) => service.zone || "—")));
  const groups = orderedZones.map((zone) => {
    const members = services.filter((service) => (service.zone || "—") === zone);
    if (!members.length) return "";
    const rows = members.map((service) => {
      const ports = (service.ports || []).join(", ");
      return `<div class="service-row">
        <code>${escapeHtml(service.id)}</code>
        <span class="kind">${escapeHtml(service.kind || "service")}</span>
        ${ports ? `<span class="ports">:${escapeHtml(ports)}</span>` : ""}
      </div>`;
    }).join("");
    return `<div class="zone-group">
      <div class="zone-head">${escapeHtml(zone)}</div>
      ${rows}
    </div>`;
  }).join("");
  document.getElementById("world").innerHTML = groups;
}

function renderLineage() {
  const nodes = model.lineage.nodes || [];
  document.getElementById("lineage-count").textContent = plural(nodes.length, "node");
  document.getElementById("lineage").innerHTML = nodes.length
    ? nodes.map((node) => {
        const summary = node.builder_summary || node.prompt || "";
        const files = (node.touched_files || []).join(" · ");
        return `<div class="lineage-node">
          <h3>${escapeHtml(node.id)}</h3>
          ${summary ? `<p class="summary">${escapeHtml(summary)}</p>` : ""}
          ${files ? `<p class="meta">${escapeHtml(files)}</p>` : ""}
        </div>`;
      }).join("")
    : emptyCard("No lineage steps recorded.");
}

function renderArtifacts() {
  const artifacts = model.topology.artifact_paths || [];
  document.getElementById("artifact-count").textContent = String(artifacts.length);
  document.getElementById("artifacts").innerHTML = artifacts.length
    ? `<div class="artifact-grid">${artifacts.map((path) => (
        `<code>${escapeHtml(path)}</code>`
      )).join("")}</div>`
    : emptyCard("No artifacts recorded.");
}

function emptyCard(message) {
  return `<p class="empty-card">${escapeHtml(message)}</p>`;
}

function render() {
  renderInspector();
  renderSimulation();
  renderBriefing();
  renderTasks();
  renderAdmission();
  renderWorld();
  renderLineage();
  renderArtifacts();
}

async function refresh() {
  const [briefing, actors, topology, lineage, state, narration] = await Promise.all([
    json("/api/briefing"),
    json("/api/actors"),
    json("/api/topology"),
    json("/api/lineage"),
    json("/api/state"),
    json("/api/narrate"),
  ]);
  model.briefing = briefing;
  model.actors = actors;
  model.topology = topology;
  model.lineage = lineage;
  model.state = state;
  model.narration = narration;
  render();
}

document.querySelectorAll("button[data-action]").forEach((button) => {
  button.addEventListener("click", async () => {
    await json(`/api/episode/${button.dataset.action}`, { method: "POST" });
    await refresh();
  });
});

function closeStreams() {
  if (runState.events) {
    runState.events.close();
    runState.events = null;
  }
  if (runState.narration) {
    runState.narration.close();
    runState.narration = null;
  }
}

// Coalesce rapid-fire SSE events (the backlog burst on reconnect can
// be 200 events in one frame) into a single refresh per ~150ms. The
// model is fetched whole anyway — there's no value in hammering the
// API once per event.
let _refreshScheduled = false;
function scheduleRefresh() {
  if (_refreshScheduled) return;
  _refreshScheduled = true;
  setTimeout(() => {
    _refreshScheduled = false;
    refresh();
  }, 150);
}

function openStreams() {
  closeStreams();
  if (!runState.activeRun) return;
  runState.events = new EventSource(withRun("/api/events/stream"));
  runState.events.addEventListener("agent_step", scheduleRefresh);
  runState.events.addEventListener("env_turn", scheduleRefresh);
  runState.events.addEventListener("note", scheduleRefresh);
  // Also catch builder_step — without this the SPA stalls in the
  // "no admitted world" empty state right after the build finishes
  // and before the first env_turn fires, since nothing else triggers
  // a topology re-fetch in that window.
  runState.events.addEventListener("builder_step", scheduleRefresh);
  runState.narration = new EventSource(withRun("/api/narrate/stream"));
  runState.narration.addEventListener("narration", scheduleRefresh);
}

function applyRunsToPicker(runs, defaultId) {
  const list = document.getElementById("sim-runs-list");
  const counter = document.getElementById("sim-runs-count");
  if (!list) return;
  if (counter) {
    counter.textContent = runs.length
      ? `${runs.length}${runState.followLatest ? " · following latest" : ""}`
      : "0";
  }
  const previous = runState.activeRun;
  if (!runs.length) {
    list.innerHTML = '<li class="sim-runs-empty">No runs found</li>';
    runState.activeRun = null;
    closeStreams();
    return;
  }
  const newest = defaultId || runs[0].id;
  let target;
  if (runState.followLatest) {
    target = newest;
  } else if (previous && runs.some((r) => r.id === previous)) {
    target = previous;
  } else {
    target = newest;
  }
  list.innerHTML = "";
  for (const run of runs) {
    const item = document.createElement("li");
    item.className = "sim-run-item" + (run.id === target ? " is-active" : "");
    item.dataset.runId = run.id;
    const ts = run.modified ? new Date(run.modified * 1000) : null;
    item.innerHTML = `
      <span class="sim-run-id">${escapeHtml(run.id)}</span>
      <span class="sim-run-meta">${escapeHtml(ts ? ts.toLocaleString() : "")}</span>
    `;
    item.addEventListener("click", () => selectRun(run.id, /* fromUser */ true));
    list.appendChild(item);
  }
  if (target !== runState.activeRun) {
    runState.activeRun = target;
    openStreams();
    refresh();
  }
}

function selectRun(runId, fromUser) {
  if (!runId || runId === runState.activeRun) return;
  if (fromUser) {
    const followToggle = document.getElementById("sim-run-follow");
    if (followToggle && followToggle.checked) {
      followToggle.checked = false;
      runState.followLatest = false;
    }
  }
  runState.activeRun = runId;
  document.querySelectorAll(".sim-run-item").forEach((el) => {
    el.classList.toggle("is-active", el.dataset.runId === runId);
  });
  const counter = document.getElementById("sim-runs-count");
  if (counter && runState.runs.length) {
    counter.textContent = `${runState.runs.length}${
      runState.followLatest ? " · following latest" : ""
    }`;
  }
  openStreams();
  refresh();
}

function setRunsDrawerOpen(open) {
  const drawer = document.getElementById("sim-runs-drawer");
  const toggle = document.getElementById("sim-runs-toggle");
  if (!drawer || !toggle) return;
  drawer.classList.toggle("is-open", open);
  drawer.setAttribute("aria-hidden", open ? "false" : "true");
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
}

async function refreshRuns() {
  try {
    const payload = await fetch("/api/runs").then((r) => r.json());
    runState.runs = payload.runs || [];
    applyRunsToPicker(runState.runs, payload.default || null);
  } catch (err) {
    console.warn("failed to list runs", err);
  }
}

document.getElementById("sim-run-follow").addEventListener("change", async (e) => {
  runState.followLatest = e.target.checked;
  if (runState.followLatest) {
    await refreshRuns();
  } else {
    applyRunsToPicker(runState.runs, null);
  }
});

document.getElementById("sim-runs-toggle").addEventListener("click", () => {
  const drawer = document.getElementById("sim-runs-drawer");
  const open = drawer && !drawer.classList.contains("is-open");
  setRunsDrawerOpen(open);
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    setRunsDrawerOpen(false);
  }
});

(async () => {
  await refreshRuns();
  await refresh();
  // Re-discover runs every 5s so a fresh run dir created by the
  // writer mid-session shows up.
  setInterval(async () => {
    await refreshRuns();
  }, 5000);
  // Polling refresh as a fallback for the SSE stream. SSE is the
  // primary live-update path; the poll catches up the UI if the
  // SSE connection ever drops silently (browser-side
  // disconnects, intermediary timeouts, etc.) — without it the SPA
  // can land on a snapshot that's older than the on-disk state.
  setInterval(async () => {
    if (runState.activeRun) await refresh();
  }, 2000);
})();
