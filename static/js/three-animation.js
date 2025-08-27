/**
 * Three.js Animation for PhantomStrike
 * Creates an interactive 3D background with security-themed models
 */

// Initialize variables
let scene, camera, renderer, controls;
let particleSystem, shield, lockModel;
let raycaster, mouse;
let animationId;
let modelGroup;

// Colors
const ACCENT_COLOR = 0x4FD1C5;
const GLOW_COLOR = 0x4fd1c5;

// Settings
const PARTICLE_COUNT = 1000;
const PARTICLE_SPEED = 0.05;

/**
 * Initialize the Three.js scene
 */
function initThreeAnimation() {
    const container = document.getElementById('animation-container');
    if (!container) return;

    // Scene setup
    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(60, container.clientWidth / container.clientHeight, 0.1, 1000);
    camera.position.z = 10;
    
    // Renderer
    renderer = new THREE.WebGLRenderer({ 
        antialias: true,
        alpha: true 
    });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);
    
    // Controls
    controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.enableZoom = false;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.5;
    
    // Raycaster for interactivity
    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();
    
    // Lights
    addLights();
    
    // Add particle system
    createParticles();
    
    // Add 3D models
    modelGroup = new THREE.Group();
    scene.add(modelGroup);
    
    // Create shield model
    createShield();
    
    // Handle window resize
    window.addEventListener('resize', onWindowResize);
    
    // Make models interactive
    container.addEventListener('mousemove', onMouseMove);
    container.addEventListener('click', onMouseClick);
    
    // Start animation loop
    animate();
}

/**
 * Add lighting to the scene
 */
function addLights() {
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
    scene.add(ambientLight);
    
    const pointLight1 = new THREE.PointLight(ACCENT_COLOR, 1, 100);
    pointLight1.position.set(10, 10, 10);
    scene.add(pointLight1);
    
    const pointLight2 = new THREE.PointLight(0xffffff, 1, 100);
    pointLight2.position.set(-10, -10, -10);
    scene.add(pointLight2);
}

/**
 * Create particle system for background effect
 */
function createParticles() {
    const particles = new THREE.BufferGeometry();
    const positions = [];
    const colors = [];
    const sizes = [];
    
    const color = new THREE.Color(ACCENT_COLOR);
    
    for (let i = 0; i < PARTICLE_COUNT; i++) {
        // Position
        const x = Math.random() * 40 - 20;
        const y = Math.random() * 40 - 20;
        const z = Math.random() * 40 - 20;
        positions.push(x, y, z);
        
        // Color
        const brightness = 0.5 + Math.random() * 0.5;
        colors.push(color.r * brightness, color.g * brightness, color.b * brightness);
        
        // Size
        sizes.push(Math.random() * 0.1 + 0.05);
    }
    
    particles.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    particles.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
    particles.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));
    
    const particleMaterial = new THREE.ShaderMaterial({
        uniforms: {
            time: { value: 0 },
            pointTexture: { value: new THREE.TextureLoader().load('/static/img/particle.svg') }
        },
        vertexShader: `
            attribute float size;
            varying vec3 vColor;
            uniform float time;
            
            void main() {
                vColor = color;
                vec3 pos = position;
                
                // Subtle movement
                pos.x += sin(time * 0.2 + position.z * 0.5) * 0.1;
                pos.y += cos(time * 0.2 + position.x * 0.5) * 0.1;
                pos.z += sin(time * 0.2 + position.y * 0.5) * 0.1;
                
                vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
                gl_PointSize = size * (300.0 / -mvPosition.z);
                gl_Position = projectionMatrix * mvPosition;
            }
        `,
        fragmentShader: `
            uniform sampler2D pointTexture;
            varying vec3 vColor;
            
            void main() {
                gl_FragColor = vec4(vColor, 1.0) * texture2D(pointTexture, gl_PointCoord);
            }
        `,
        blending: THREE.AdditiveBlending,
        depthTest: false,
        transparent: true,
        vertexColors: true
    });
    
    particleSystem = new THREE.Points(particles, particleMaterial);
    scene.add(particleSystem);
}

/**
 * Create shield model
 */
function createShield() {
    // Shield geometry
    const shieldGeometry = new THREE.SphereGeometry(2.5, 32, 32, 0, Math.PI * 2, 0, Math.PI * 0.65);
    
    // Shield material
    const shieldMaterial = new THREE.MeshPhysicalMaterial({
        color: ACCENT_COLOR,
        metalness: 0.2,
        roughness: 0.3,
        transparent: true,
        opacity: 0.7,
        side: THREE.DoubleSide,
        envMapIntensity: 1.5,
        clearcoat: 1.0,
        clearcoatRoughness: 0.2
    });
    
    shield = new THREE.Mesh(shieldGeometry, shieldMaterial);
    shield.rotation.x = Math.PI;
    shield.position.y = -0.5;
    modelGroup.add(shield);
    
    // Create glowing core
    const coreGeometry = new THREE.IcosahedronGeometry(0.8, 2);
    const coreMaterial = new THREE.MeshLambertMaterial({
        color: GLOW_COLOR,
        emissive: GLOW_COLOR,
        emissiveIntensity: 0.5
    });
    
    const core = new THREE.Mesh(coreGeometry, coreMaterial);
    core.position.y = 0.5;
    modelGroup.add(core);
    
    // Add hexagon ring around shield
    const hexRingGeometry = new THREE.TorusGeometry(3.2, 0.1, 16, 6);
    const hexRingMaterial = new THREE.MeshLambertMaterial({
        color: ACCENT_COLOR,
        emissive: ACCENT_COLOR,
        emissiveIntensity: 0.3
    });
    
    const hexRing = new THREE.Mesh(hexRingGeometry, hexRingMaterial);
    hexRing.rotation.x = Math.PI / 2;
    hexRing.position.y = -0.5;
    modelGroup.add(hexRing);
    
    // Add cybersecurity symbols
    addCyberSecuritySymbols();
}

/**
 * Add small cybersecurity-themed symbols around the shield
 */
function addCyberSecuritySymbols() {
    // Create a circular pattern of small symbols
    const symbolCount = 8;
    const radius = 4;
    
    for (let i = 0; i < symbolCount; i++) {
        const angle = (i / symbolCount) * Math.PI * 2;
        const x = Math.cos(angle) * radius;
        const z = Math.sin(angle) * radius;
        
        // Alternate between lock and key symbols
        if (i % 2 === 0) {
            createLockSymbol(x, -0.5, z, 0.3);
        } else {
            createKeySymbol(x, -0.5, z, 0.3);
        }
    }
}

/**
 * Create a lock symbol at the given position
 */
function createLockSymbol(x, y, z, scale) {
    // Lock body
    const lockBodyGeometry = new THREE.BoxGeometry(1, 1.5, 0.5);
    const lockMaterial = new THREE.MeshPhongMaterial({
        color: ACCENT_COLOR,
        emissive: ACCENT_COLOR,
        emissiveIntensity: 0.2,
        shininess: 100
    });
    
    const lockBody = new THREE.Mesh(lockBodyGeometry, lockMaterial);
    
    // Lock shackle
    const shackleGeometry = new THREE.TorusGeometry(0.3, 0.1, 8, 16, Math.PI);
    const shackle = new THREE.Mesh(shackleGeometry, lockMaterial);
    shackle.rotation.x = Math.PI / 2;
    shackle.position.y = 0.7;
    
    // Combine into one object
    const lock = new THREE.Group();
    lock.add(lockBody);
    lock.add(shackle);
    
    // Position and scale
    lock.position.set(x, y, z);
    lock.scale.set(scale, scale, scale);
    lock.lookAt(0, y, 0); // Look toward center
    
    modelGroup.add(lock);
    return lock;
}

/**
 * Create a key symbol at the given position
 */
function createKeySymbol(x, y, z, scale) {
    // Key handle
    const handleGeometry = new THREE.TorusGeometry(0.4, 0.1, 8, 16);
    const keyMaterial = new THREE.MeshPhongMaterial({
        color: ACCENT_COLOR,
        emissive: ACCENT_COLOR,
        emissiveIntensity: 0.2,
        shininess: 100
    });
    
    const handle = new THREE.Mesh(handleGeometry, keyMaterial);
    
    // Key shaft
    const shaftGeometry = new THREE.CylinderGeometry(0.1, 0.1, 1.5, 8);
    const shaft = new THREE.Mesh(shaftGeometry, keyMaterial);
    shaft.rotation.x = Math.PI / 2;
    shaft.position.z = -0.8;
    
    // Key teeth
    const teeth = new THREE.Group();
    const toothGeometry = new THREE.BoxGeometry(0.15, 0.15, 0.15);
    
    for (let i = 0; i < 3; i++) {
        const tooth = new THREE.Mesh(toothGeometry, keyMaterial);
        tooth.position.set(0, -0.2, -1.1 + (i * 0.3));
        teeth.add(tooth);
    }
    
    // Combine into one object
    const key = new THREE.Group();
    key.add(handle);
    key.add(shaft);
    key.add(teeth);
    
    // Position and scale
    key.position.set(x, y, z);
    key.scale.set(scale, scale, scale);
    key.lookAt(0, y, 0); // Look toward center
    
    modelGroup.add(key);
    return key;
}

/**
 * Handle window resize
 */
function onWindowResize() {
    const container = document.getElementById('animation-container');
    if (!container) return;
    
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
}

/**
 * Handle mouse movement for interactive elements
 */
function onMouseMove(event) {
    const container = document.getElementById('animation-container');
    if (!container) return;
    
    // Calculate mouse position in normalized device coordinates
    const rect = container.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / container.clientWidth) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / container.clientHeight) * 2 + 1;
}

/**
 * Handle mouse clicks on objects
 */
function onMouseClick(event) {
    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(modelGroup.children, true);
    
    if (intersects.length > 0) {
        // Apply special effect to clicked objects
        const object = intersects[0].object;
        if (object.material) {
            const originalColor = object.material.color.getHex();
            object.material.emissiveIntensity = 1.0;
            
            // Reset after animation
            setTimeout(() => {
                object.material.emissiveIntensity = 0.2;
            }, 300);
        }
    }
}

/**
 * Animation loop
 */
function animate() {
    animationId = requestAnimationFrame(animate);
    
    // Update particle system time
    if (particleSystem && particleSystem.material.uniforms) {
        particleSystem.material.uniforms.time.value += PARTICLE_SPEED;
    }
    
    // Rotate the model group
    if (modelGroup) {
        modelGroup.rotation.y += 0.002;
    }
    
    // Animate shield pulsing effect
    if (shield) {
        const pulseFactor = Math.sin(Date.now() * 0.001) * 0.1 + 0.9;
        shield.scale.set(pulseFactor, pulseFactor, pulseFactor);
    }
    
    // Update controls
    if (controls) controls.update();
    
    // Render scene
    renderer.render(scene, camera);
}

/**
 * Clean up Three.js resources
 */
function cleanupThreeAnimation() {
    if (animationId) {
        cancelAnimationFrame(animationId);
    }
    
    if (renderer) {
        renderer.dispose();
    }
    
    const container = document.getElementById('animation-container');
    if (container && renderer && renderer.domElement) {
        container.removeChild(renderer.domElement);
    }
    
    window.removeEventListener('resize', onWindowResize);
}

// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('animation-container')) {
        initThreeAnimation();
    }
});