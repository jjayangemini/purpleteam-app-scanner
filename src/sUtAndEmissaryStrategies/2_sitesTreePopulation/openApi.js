// Copyright (C) 2017-2022 BinaryMist Limited. All rights reserved.

// Use of this software is governed by the Business Source License
// included in the file /licenses/bsl.md

// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

import { promises as fsPromises } from 'fs';
import * as oldfs from "fs";
import { promisify } from 'util';
import { randomBytes } from 'crypto';
import config from '../../../config/config.js';
import SitesTreePopulation from './strategy.js';

const rndBytes = promisify(randomBytes);

// Doc: https://www.zaproxy.org/docs/desktop/addons/openapi-support/

class OpenApi extends SitesTreePopulation {
  #emissaryPropertiesSubSet;
  #fileName = 'openApi';

  constructor({ log, publisher, baseUrl, sutPropertiesSubSet, setContextId, emissaryPropertiesSubSet, zAp }) {
    super({ publisher, baseUrl, sutPropertiesSubSet, setContextId, zAp });
    this.log = log;
    this.#emissaryPropertiesSubSet = emissaryPropertiesSubSet;
  }

  async #importDefinitionFromUrl({ importUrl, testSessionId, contextId }) {
    const methodName = '#importDefinitionFromUrl';
    await this.zAp.aPi.openapi.importUrl({ url: importUrl, hostOverride: this.baseUrl, contextId })
      .then((resp) => {
        this.publisher.pubLog({ testSessionId, logLevel: 'info', textData: `Loaded OpenAPI definition from URL into the Emissary, for Test Session with id: "${testSessionId}". Response was: ${JSON.stringify(resp)}.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
      }).catch((err) => {
        const buildUserErrorText = 'Error occurred while attempting to load the OpenAPI definition from URL into the Emissary';
        const adminErrorText = `${buildUserErrorText}, for Test Session with id: "${testSessionId}", Error was: ${err.message}`;
        this.publisher.publish({ testSessionId, textData: `${buildUserErrorText}.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
        this.log.error(adminErrorText, { tags: [`pid-${process.pid}`, this.#fileName, methodName] });
        throw new Error(adminErrorText);
      });
  }

  async #importDefinitionFromFileContent({ importFileContentBase64, testSessionId, contextId }) {
    const methodName = '#importDefinitionFromFileContent';
    const { dir: appTesterUploadDir } = config.get('upload');
    const emissaryUploadDir = this.#emissaryPropertiesSubSet;

    // Need to copy file as unique name so that another Test Session is unable to delete it before we load it into the Emissary.
    let rndFilePrefix = '';
    await rndBytes(4)
      .then((buf) => {
        rndFilePrefix = buf.toString('hex');
      })
      .catch((err) => {
        const adminErrorText = `Error (non fatal) occurred while attempting to get randomBytes for file prefix, for Test Session with id: "${testSessionId}", Error was: ${err.message}`;
        this.log.error(adminErrorText, { tags: [`pid-${process.pid}`, this.#fileName, methodName] });
      });
    const fileNameNoPrefix = 'OpenApiDefinition';
    const fileNameWithPrefix = `${rndFilePrefix}-${fileNameNoPrefix}`;
    const buff = Buffer.from(importFileContentBase64, 'base64');
      
    await fsPromises.writeFile(`${appTesterUploadDir}${fileNameWithPrefix}`, buff)
      .then(() => {
        this.publisher.pubLog({ testSessionId, logLevel: 'info', textData: `OpenAPI definition: "${appTesterUploadDir}${fileNameWithPrefix}" was successfully written to the App Tester upload directory.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
      })
      .catch((err) => {
        const buildUserErrorText = `Error occurred while attempting to write the OpenAPI definition from file: "${fileNameNoPrefix}" to the App Tester upload directory for the Emissary consumption`;
        const adminErrorText = `${buildUserErrorText}, for Test Session with id: "${testSessionId}", Error was: ${err.message}`;
        this.publisher.publish({ testSessionId, textData: `${buildUserErrorText}.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
        this.log.error(adminErrorText, { tags: [`pid-${process.pid}`, this.#fileName, methodName] });
        throw new Error(adminErrorText);
      });

    await fsPromises.access(`${appTesterUploadDir}${fileNameWithPrefix}`, oldfs.constants.F_OK)
      .then(() => {
        this.publisher.pubLog({ testSessionId, logLevel: 'info', textData: `OpenAPI definition: "${appTesterUploadDir}${fileNameWithPrefix}" can be accessed.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
      })
      .catch((err) => {
        const buildUserErrorText = `Error occurred while attempting to access the OpenAPI definition from file: "${fileNameNoPrefix}" to the App Tester upload directory for the Emissary consumption`;
        const adminErrorText = `${buildUserErrorText}, for Test Session with id: "${testSessionId}", Error was: ${err.message}`;
        this.publisher.publish({ testSessionId, textData: `${buildUserErrorText}.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
        this.log.error(adminErrorText, { tags: [`pid-${process.pid}`, this.#fileName, methodName] });
        throw new Error(adminErrorText);
      });

    await this.zAp.aPi.openapi.importFile({ file: `${emissaryUploadDir}${fileNameWithPrefix}`, target: this.baseUrl, contextId })
      .then((resp) => {
        this.publisher.pubLog({ testSessionId, logLevel: 'info', textData: `Loaded OpenAPI definition from file: "${fileNameNoPrefix}" into the Emissary, for Test Session with id: "${testSessionId}". Response was: ${JSON.stringify(resp)}.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
      }).catch((err) => {
        const buildUserErrorText = `Error occurred while attempting to load the OpenAPI definition from file: "${emissaryUploadDir}${fileNameWithPrefix}" into the Emissary ${this.baseUrl}`;
        const adminErrorText = `${buildUserErrorText}, for Test Session with id: "${testSessionId}", Error was: ${err.message}`;
        this.publisher.publish({ testSessionId, textData: `${buildUserErrorText}.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
        this.log.error(adminErrorText, { tags: [`pid-${process.pid}`, this.#fileName, methodName] });
        throw new Error(adminErrorText);
      });
    await fsPromises.rm(`${appTesterUploadDir}${fileNameWithPrefix}`)
      .then(() => {
        this.publisher.pubLog({ testSessionId, logLevel: 'info', textData: `Removed OpenAPI definition file: "${fileNameNoPrefix}" from the App Tester upload directory.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
      })
      .catch((err) => {
        const buildUserErrorText = `Error occurred while attempting to remove the OpenAPI definition file: "${fileNameNoPrefix}" from the App Tester upload directory after loading into the Emissary`;
        const adminErrorText = `${buildUserErrorText}, for Test Session with id: "${testSessionId}", Error was: ${err.message}`;
        this.publisher.publish({ testSessionId, textData: `${buildUserErrorText}.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });
        this.log.error(adminErrorText, { tags: [`pid-${process.pid}`, this.#fileName, methodName] });
      });
  }

  async populate() {
    const methodName = 'populate';
    const {
      testSession: { id: testSessionId, attributes: { openApi: { importFileContentBase64, importUrl } } },
      context: { name: contextName }
    } = this.sutPropertiesSubSet;

    this.publisher.pubLog({ testSessionId, logLevel: 'info', textData: `The ${methodName}() method of the ${super.constructor.name} strategy "${this.constructor.name}" has been invoked.`, tagObj: { tags: [`pid-${process.pid}`, this.#fileName, methodName] } });

    const contextId = await this.setContextIdForSut(testSessionId, contextName);

    importUrl ? await this.#importDefinitionFromUrl({ importUrl, testSessionId, contextId }) : await this.#importDefinitionFromFileContent({ importFileContentBase64, testSessionId, contextId });
  }
}

export default OpenApi;
