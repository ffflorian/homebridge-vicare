import request from 'request';
import crypto from 'node:crypto';
import open from 'open';
import http from 'node:http';
import {internalIpV4} from 'internal-ip';

import {
  CharacteristicValue as HomebridgeCharacteristicValue,
  API as HomebridgeAPI,
  Characteristic as HomebridgeCharacteristic,
  Logging as HomebridgeLogging,
  PlatformAccessory as HomebridgePlatformAccessory,
  PlatformConfig as HomebridgePlatformConfig,
  Service as HomebridgeService,
  uuid,
  CharacteristicSetCallback,
} from 'homebridge';

interface ViessmannAPIResponse<T> {
  data: T;
}

interface ViessmannSmartComponent {
  id: string;
  name: string;
  selected: boolean;
  deleted: boolean;
}

interface LocalDevice {
  name: string;
  feature: string;
  deviceId: string;
}

interface LocalPlatform {
  platform: string;
  name: string;
  clientId: string;
  apiEndpoint: string;
  devices: LocalDevice[];
}

interface LocalConfig {
  platforms: LocalPlatform[];
}

let Service: typeof HomebridgeService;
let Characteristic: typeof HomebridgeCharacteristic;
let Accessory: typeof HomebridgePlatformAccessory;
let UUIDGen: typeof uuid;

export default (homebridge: HomebridgeAPI) => {
  Service = homebridge.hap.Service;
  Characteristic = homebridge.hap.Characteristic;
  Accessory = homebridge.platformAccessory;
  UUIDGen = homebridge.hap.uuid;
  homebridge.registerPlatform('homebridge-vicare', 'ViCareThermostatPlatform', ViCareThermostatPlatform);
};

class ViCareThermostatPlatform {
  private accessories: HomebridgePlatformAccessory[];
  private accessToken?: string;
  private api: HomebridgeAPI;
  private apiEndpoint: string;
  private clientId: string;
  private codeChallenge: string;
  private codeVerifier: string;
  private devices: Array<HomebridgePlatformConfig & LocalConfig>;
  private hostIp?: string;
  private log: HomebridgeLogging;
  private redirectUri?: string;
  private installationId?: string;
  private gatewaySerial?: string;

  config: HomebridgePlatformConfig & LocalConfig;

  constructor(log: HomebridgeLogging, config: HomebridgePlatformConfig & LocalConfig, api: HomebridgeAPI) {
    this.log = log;
    this.config = config;
    this.api = api;
    this.clientId = config.clientId;
    this.apiEndpoint = config.apiEndpoint;
    this.devices = config.devices;
    this.accessories = [];
    this.codeVerifier = this.generateCodeVerifier();
    this.codeChallenge = this.generateCodeChallenge(this.codeVerifier);

    this.api.on('didFinishLaunching', async () => {
      this.log('Starting authentication process...');
      this.hostIp = await internalIpV4(); // Ermittelt die lokale IP-Adresse
      this.redirectUri = `http://${this.hostIp}:4200`;
      this.log(`Using redirect URI: ${this.redirectUri}`);
      try {
        const {accessToken} = await this.authenticate();
        this.log('Authentication successful, received access token.');
        this.accessToken = accessToken;
        try {
          const {installationId, gatewaySerial} = await this.retrieveIds();
          if (installationId && gatewaySerial) {
            this.log('Retrieved installation and gateway IDs.');
            this.installationId = installationId;
            this.gatewaySerial = gatewaySerial;
            this.devices.forEach(deviceConfig => {
              this.addAccessory(deviceConfig);
            });
            this.retrieveSmartComponents();
          } else {
            this.log('Error retrieving installation or gateway IDs');
          }
        } catch (error) {
          this.log('Error retrieving installation or gateway IDs:', error);
        }
      } catch (error) {
        this.log('Error during authentication:', error);
      }
    });
  }

  configureAccessory(accessory: HomebridgePlatformAccessory) {
    this.accessories.push(accessory);
  }

  generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url');
  }

  generateCodeChallenge(codeVerifier: string) {
    return crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  }

  async authenticate(): Promise<{accessToken: string}> {
    const authUrl = `https://iam.viessmann.com/idp/v3/authorize?client_id=${this.clientId}&redirect_uri=${encodeURIComponent(this.redirectUri!)}&scope=IoT%20User%20offline_access&response_type=code&code_challenge_method=S256&code_challenge=${
      this.codeChallenge
    }`;

    this.log(`Opening browser for authentication: ${authUrl}`);
    await open(authUrl);

    return await this.startServer();
  }

  startServer(): Promise<{accessToken: string}> {
    return new Promise(resolve => {
      let server = http
        .createServer((req, res) => {
          const url = new URL(req.url || '127.0.0.1', `http://${req.headers.host}`);
          const authCode = url.searchParams.get('code');
          if (authCode) {
            this.log('Received authorization code:', authCode);
            res.writeHead(200, {'Content-Type': 'text/plain'});
            res.end('Authorization successful. You can close this window.');
            this.exchangeCodeForToken(authCode).then(({accessToken}) => {
              server.close();
              resolve({accessToken});
            });
          } else {
            res.writeHead(400, {'Content-Type': 'text/plain'});
            res.end('Authorization code not found.');
          }
        })
        .listen(4200, this.hostIp, () => {
          this.log(`Server is listening on ${this.hostIp}:4200`);
        });
    });
  }

  exchangeCodeForToken(authCode: string): Promise<{accessToken: string}> {
    const tokenUrl = 'https://iam.viessmann.com/idp/v3/token';
    const params = {
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      grant_type: 'authorization_code',
      code_verifier: this.codeVerifier,
      code: authCode,
    };

    this.log('Exchanging authorization code for access token...');

    return new Promise((resolve, reject) => {
      request.post(
        {
          url: tokenUrl,
          form: params,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
        (error, response, body) => {
          if (error || response.statusCode !== 200) {
            this.log('Error exchanging code for token:', error || body);
            return reject(error || new Error(body));
          }

          this.log('Successfully exchanged code for access token.');
          const tokenResponse = JSON.parse(body);
          resolve({accessToken: tokenResponse.access_token});
        }
      );
    });
  }

  retrieveIds(): Promise<{installationId?: string; gatewaySerial?: string}> {
    const options = {
      url: `${this.apiEndpoint}/equipment/installations`,
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
      },
      json: true,
    };

    this.log('Retrieving installation IDs...');

    return new Promise((resolve, reject) => {
      request.get(options, (error, response, body) => {
        if (error || response.statusCode !== 200) {
          this.log('Error retrieving installations:', error || body);
          throw error || new Error(body);
        }

        this.log('Successfully retrieved installations:', body);
        const installation = body.data[0];
        const installationId = installation.id;

        const gatewayOptions = {
          url: `${this.apiEndpoint}/equipment/installations/${installationId}/gateways`,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
          },
          json: true,
        };

        this.log('Retrieving gateway IDs...');
        request.get(gatewayOptions, (error, response, body) => {
          if (error || response.statusCode !== 200) {
            this.log('Error retrieving gateways:', error || body);
            return reject(error || new Error(body));
          }

          this.log('Successfully retrieved gateways:', body);

          if (!body.data || body.data.length === 0) {
            this.log('No gateway data available.');
            return reject(new Error('No gateway data available.'));
          }

          const gateway = body.data[0];
          const gatewaySerial = gateway.serial;
          resolve({installationId, gatewaySerial});
        });
      });
    });
  }

  retrieveSmartComponents() {
    const options = {
      url: `${this.apiEndpoint}/equipment/installations/${this.installationId}/smartComponents`,
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
      },
      json: true,
    };

    this.log('Retrieving smart components...');
    request.get(options, (error, response, body: ViessmannAPIResponse<ViessmannSmartComponent[]>) => {
      if (error || response.statusCode !== 200) {
        this.log('Error retrieving smart components:', error || body);
        return;
      }

      this.log('Successfully retrieved smart components:', body);
      body.data.forEach(component => {
        this.log(
          `Component ID: ${component.id}, Name: ${component.name}, Selected: ${component.selected}, Deleted: ${component.deleted}`
        );
      });
    });
  }

  selectSmartComponents(componentIds: string[]): Promise<{result: ViessmannAPIResponse<ViessmannSmartComponent[]>}> {
    const options = {
      url: `${this.apiEndpoint}/equipment/installations/${this.installationId}/smartComponents`,
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({selected: componentIds}),
    };

    this.log('Selecting smart components...');

    return new Promise((resolve, reject) => {
      request.put(options, (error, response, body: string) => {
        if (error || response.statusCode !== 200) {
          this.log('Error selecting smart components:', error || body);
          return reject(error || new Error(body));
        }

        const result: ViessmannAPIResponse<ViessmannSmartComponent[]> = JSON.parse(body);
        this.log('Successfully selected smart components:', result);
        resolve({result});
      });
    });
  }

  addAccessory(deviceConfig: HomebridgePlatformConfig & LocalConfig): void {
    const uuid = UUIDGen.generate(deviceConfig.name || new Date().getTime().toString());
    let accessory = this.accessories.find(acc => acc.UUID === uuid);

    if (!accessory) {
      accessory = new Accessory(deviceConfig.name || new Date().getTime().toString(), uuid);
      this.api.registerPlatformAccessories('homebridge-vicare', 'ViCareThermostatPlatform', [accessory]);
      this.accessories.push(accessory);
      this.log(`Added new accessory: ${deviceConfig.name}`);
    }

    const vicareAccessory = new ViCareThermostatAccessory(
      this.log,
      deviceConfig,
      this.api,
      this.accessToken!,
      this.apiEndpoint,
      this.installationId!,
      this.gatewaySerial!
    );

    accessory.context.deviceConfig = deviceConfig;
    accessory
      .getService(Service.AccessoryInformation)
      ?.setCharacteristic(Characteristic.Manufacturer, 'Viessmann')
      .setCharacteristic(Characteristic.Model, 'ViCare')
      .setCharacteristic(Characteristic.SerialNumber, 'Default-Serial');

    vicareAccessory.getServices().forEach(service => {
      const existingService = accessory.getServiceById(service.UUID, service.subtype || '');
      if (existingService) {
        accessory.removeService(existingService);
      }
      accessory.addService(service);
    });

    this.api.updatePlatformAccessories([accessory]);
  }
}

class ViCareThermostatAccessory {
  private log: HomebridgeLogging;
  private name?: string;
  private feature: string;
  private apiEndpoint: string;
  private accessToken: string;
  private deviceId: string;
  private installationId: string;
  private gatewaySerial: string;
  private temperatureService: HomebridgeService;
  private services: HomebridgeService[];
  private switchService?: HomebridgeService;

  constructor(
    log: HomebridgeLogging,
    config: HomebridgePlatformConfig,
    _api: HomebridgeAPI,
    accessToken: string,
    apiEndpoint: string,
    installationId: string,
    gatewaySerial: string
  ) {
    this.log = log;
    this.name = config.name;
    this.feature = config.feature;
    this.apiEndpoint = apiEndpoint;
    this.accessToken = accessToken;
    this.deviceId = config.deviceId;
    this.installationId = installationId;
    this.gatewaySerial = gatewaySerial;

    this.temperatureService = new Service.TemperatureSensor(
      this.name,
      `temperatureService_${this.name}_${this.feature}_${UUIDGen.generate(this.name + this.feature)}`
    );
    this.temperatureService
      .getCharacteristic(Characteristic.CurrentTemperature)
      .on('get', this.getTemperature.bind(this));

    if (config.feature.includes('burners')) {
      this.switchService = new Service.Switch(
        this.name,
        `switchService_${this.name}_${this.feature}_${UUIDGen.generate(this.name + this.feature)}`
      );
      this.switchService
        .getCharacteristic(Characteristic.On)
        .on('get', this.getBurnerStatus.bind(this))
        .on('set', this.setBurnerStatus.bind(this));
    }

    this.services = [this.temperatureService];
    if (this.switchService) {
      this.services.push(this.switchService);
    }
  }

  getTemperature(): Promise<{temp: number}> {
    const url = `${this.apiEndpoint}/features/installations/${this.installationId}/gateways/${this.gatewaySerial}/devices/${this.deviceId}/features/${this.feature}`;
    this.log(`Fetching temperature from ${url}`);
    return new Promise((resolve, reject) => {
      request.get(
        {
          url: url,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
          },
          json: true,
        },
        (error, response, body) => {
          if (!error && response.statusCode === 200) {
            const data = body.data || body;
            if (data.properties && data.properties.value && data.properties.value.value !== undefined) {
              const temp = data.properties.value.value;
              resolve({temp});
            } else {
              this.log('Unexpected response structure:', data);
              reject(new Error('Unexpected response structure.'));
            }
          } else {
            this.log('Error fetching temperature:', error || body);
            reject(error || new Error(body));
          }
        }
      );
    });
  }

  getBurnerStatus(): Promise<{isActive: boolean}> {
    const url = `${this.apiEndpoint}/features/installations/${this.installationId}/gateways/${this.gatewaySerial}/devices/${this.deviceId}/features/${this.feature}`;
    this.log(`Fetching burner status from ${url}`);

    return new Promise((resolve, reject) => {
      request.get(
        {
          url: url,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
          },
          json: true,
        },
        (error, response, body) => {
          if (!error && response.statusCode === 200) {
            const data = body.data || body;
            if (data.properties && data.properties.active && data.properties.active.value !== undefined) {
              const isActive = data.properties.active.value;
              resolve({isActive});
            } else {
              this.log('Unexpected response structure:', data);
              reject(new Error('Unexpected response structure.'));
            }
          } else {
            this.log('Error fetching burner status:', error || body);
            reject(error || new Error(body));
          }
        }
      );
    });
  }

  setBurnerStatus(_value: HomebridgeCharacteristicValue, callback: CharacteristicSetCallback) {
    callback(null);
  }

  getServices() {
    return this.services;
  }
}
