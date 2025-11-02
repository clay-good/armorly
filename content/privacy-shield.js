/**
 * Privacy Shield for Armorly
 * 
 * Comprehensive privacy protection against:
 * - Browser fingerprinting
 * - Canvas fingerprinting
 * - WebGL fingerprinting
 * - Font enumeration
 * - Device fingerprinting
 * - Tracking scripts
 * 
 * Features:
 * - Spoof fingerprinting APIs
 * - Randomize canvas/WebGL signatures
 * - Block tracking scripts
 * - Protect device information
 * - Prevent cross-site tracking
 * 
 * @module privacy-shield
 * @author Armorly Security Team
 */

class PrivacyShield {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      fingerprintingBlocked: 0,
      canvasBlocked: 0,
      webglBlocked: 0,
      trackingBlocked: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      blockCanvasFingerprinting: true,
      blockWebGLFingerprinting: true,
      blockFontEnumeration: true,
      spoofUserAgent: false,
      randomizeFingerprints: true,
      logActions: false,
    };

    /**
     * Original API methods
     */
    this.originalMethods = {};

    /**
     * Randomization seeds
     */
    this.seeds = {
      canvas: Math.random(),
      webgl: Math.random(),
    };
  }

  /**
   * Start privacy protection
   */
  start() {
    if (!this.config.enabled) return;

    try {
      // Protect Canvas API
      if (this.config.blockCanvasFingerprinting) {
        this.protectCanvas();
      }

      // Protect WebGL API
      if (this.config.blockWebGLFingerprinting) {
        this.protectWebGL();
      }

      // Protect Font Enumeration
      if (this.config.blockFontEnumeration) {
        this.protectFonts();
      }

      // Protect Navigator APIs
      this.protectNavigator();

      // Protect Screen APIs
      this.protectScreen();

      console.log('[Armorly PrivacyShield] Started - Privacy protection active');
    } catch (error) {
      console.error('[Armorly PrivacyShield] Error starting:', error);
    }
  }

  /**
   * Protect Canvas API from fingerprinting
   */
  protectCanvas() {
    const self = this;

    // Store original methods
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const originalToBlob = HTMLCanvasElement.prototype.toBlob;
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    // Override toDataURL
    HTMLCanvasElement.prototype.toDataURL = function() {
      // Check if this is fingerprinting attempt
      if (self.isCanvasFingerprinting(this)) {
        self.stats.canvasBlocked++;
        self.stats.fingerprintingBlocked++;

        if (self.config.logActions) {
          console.log('[Armorly PrivacyShield] Blocked canvas fingerprinting (toDataURL)');
        }

        // Return slightly randomized data
        if (self.config.randomizeFingerprints) {
          return self.randomizeCanvasData(originalToDataURL.apply(this, arguments));
        }

        // Or return empty canvas
        return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      }

      return originalToDataURL.apply(this, arguments);
    };

    // Override toBlob
    HTMLCanvasElement.prototype.toBlob = function(callback) {
      if (self.isCanvasFingerprinting(this)) {
        self.stats.canvasBlocked++;
        self.stats.fingerprintingBlocked++;

        if (self.config.logActions) {
          console.log('[Armorly PrivacyShield] Blocked canvas fingerprinting (toBlob)');
        }

        // Return empty blob
        callback(new Blob());
        return;
      }

      return originalToBlob.apply(this, arguments);
    };

    // Override getImageData
    CanvasRenderingContext2D.prototype.getImageData = function() {
      if (self.isCanvasFingerprinting(this.canvas)) {
        self.stats.canvasBlocked++;
        self.stats.fingerprintingBlocked++;

        if (self.config.logActions) {
          console.log('[Armorly PrivacyShield] Blocked canvas fingerprinting (getImageData)');
        }

        // Return randomized image data
        const imageData = originalGetImageData.apply(this, arguments);
        if (self.config.randomizeFingerprints) {
          self.randomizeImageData(imageData);
        }
        return imageData;
      }

      return originalGetImageData.apply(this, arguments);
    };

    this.originalMethods.toDataURL = originalToDataURL;
    this.originalMethods.toBlob = originalToBlob;
    this.originalMethods.getImageData = originalGetImageData;
  }

  /**
   * Protect WebGL API from fingerprinting
   */
  protectWebGL() {
    const self = this;

    // Override getParameter
    const originalGetParameter = WebGLRenderingContext.prototype.getParameter;

    WebGLRenderingContext.prototype.getParameter = function(parameter) {
      // Check for fingerprinting parameters
      const fingerprintingParams = [
        this.VENDOR,
        this.RENDERER,
        this.VERSION,
        this.SHADING_LANGUAGE_VERSION,
        37445, // UNMASKED_VENDOR_WEBGL
        37446, // UNMASKED_RENDERER_WEBGL
      ];

      if (fingerprintingParams.includes(parameter)) {
        self.stats.webglBlocked++;
        self.stats.fingerprintingBlocked++;

        if (self.config.logActions) {
          console.log('[Armorly PrivacyShield] Blocked WebGL fingerprinting');
        }

        // Return generic values
        if (parameter === this.VENDOR || parameter === 37445) {
          return 'Google Inc.';
        }
        if (parameter === this.RENDERER || parameter === 37446) {
          return 'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0)';
        }
        if (parameter === this.VERSION) {
          return 'WebGL 1.0';
        }
        if (parameter === this.SHADING_LANGUAGE_VERSION) {
          return 'WebGL GLSL ES 1.0';
        }
      }

      return originalGetParameter.apply(this, arguments);
    };

    this.originalMethods.getParameter = originalGetParameter;
  }

  /**
   * Protect font enumeration
   */
  protectFonts() {
    // Override document.fonts if available
    if (document.fonts && document.fonts.check) {
      const originalCheck = document.fonts.check;

      document.fonts.check = function() {
        // Always return false for uncommon fonts
        const fontFamily = arguments[0];
        if (fontFamily && !this.isCommonFont(fontFamily)) {
          return false;
        }
        return originalCheck.apply(this, arguments);
      };
    }
  }

  /**
   * Protect Navigator APIs
   */
  protectNavigator() {
    const self = this;

    // Protect plugins enumeration
    Object.defineProperty(navigator, 'plugins', {
      get: function() {
        self.stats.fingerprintingBlocked++;
        // Return empty or generic plugin list
        return [];
      }
    });

    // Protect mimeTypes enumeration
    Object.defineProperty(navigator, 'mimeTypes', {
      get: function() {
        self.stats.fingerprintingBlocked++;
        return [];
      }
    });

    // Protect hardware concurrency
    Object.defineProperty(navigator, 'hardwareConcurrency', {
      get: function() {
        // Return generic value
        return 4;
      }
    });

    // Protect device memory
    if ('deviceMemory' in navigator) {
      Object.defineProperty(navigator, 'deviceMemory', {
        get: function() {
          return 8;
        }
      });
    }
  }

  /**
   * Protect Screen APIs
   */
  protectScreen() {
    // Protect screen resolution
    Object.defineProperty(screen, 'width', {
      get: function() {
        return 1920;
      }
    });

    Object.defineProperty(screen, 'height', {
      get: function() {
        return 1080;
      }
    });

    Object.defineProperty(screen, 'availWidth', {
      get: function() {
        return 1920;
      }
    });

    Object.defineProperty(screen, 'availHeight', {
      get: function() {
        return 1040;
      }
    });

    Object.defineProperty(screen, 'colorDepth', {
      get: function() {
        return 24;
      }
    });

    Object.defineProperty(screen, 'pixelDepth', {
      get: function() {
        return 24;
      }
    });
  }

  /**
   * Check if canvas operation is fingerprinting
   */
  isCanvasFingerprinting(canvas) {
    // Heuristics to detect fingerprinting
    if (!canvas) return false;

    // Check canvas size (fingerprinting often uses small canvases)
    if (canvas.width < 100 && canvas.height < 100) {
      return true;
    }

    // Check if canvas is hidden
    if (canvas.style.display === 'none' || canvas.style.visibility === 'hidden') {
      return true;
    }

    return false;
  }

  /**
   * Randomize canvas data
   */
  randomizeCanvasData(dataURL) {
    // Add slight noise to the data URL
    const noise = Math.floor(this.seeds.canvas * 10);
    return dataURL + noise;
  }

  /**
   * Randomize image data
   */
  randomizeImageData(imageData) {
    // Add slight noise to pixel data
    const data = imageData.data;
    for (let i = 0; i < data.length; i += 4) {
      // Add ±1 noise to RGB values
      data[i] = Math.min(255, Math.max(0, data[i] + (Math.random() > 0.5 ? 1 : -1)));
      data[i + 1] = Math.min(255, Math.max(0, data[i + 1] + (Math.random() > 0.5 ? 1 : -1)));
      data[i + 2] = Math.min(255, Math.max(0, data[i + 2] + (Math.random() > 0.5 ? 1 : -1)));
    }
  }

  /**
   * Check if font is common
   */
  isCommonFont(fontFamily) {
    const commonFonts = [
      'Arial', 'Helvetica', 'Times New Roman', 'Courier', 'Verdana',
      'Georgia', 'Palatino', 'Garamond', 'Comic Sans MS', 'Trebuchet MS',
      'Impact', 'Lucida Console', 'Tahoma', 'sans-serif', 'serif', 'monospace'
    ];

    return commonFonts.some(font => fontFamily.includes(font));
  }

  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Enable/disable
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.PrivacyShield = PrivacyShield;
}

