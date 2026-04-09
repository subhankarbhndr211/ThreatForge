'use strict';

/**
 * ThreatForge Settings API
 * Manage AI provider and API keys from frontend
 */

const express = require('express');
const router = express.Router();

let aiSettings = {
    provider: 'groq',
    apiKey: '',
    model: '',
    customUrl: ''
};

const aiEngine = require('../aiEngine');

// Environment variable name mapping
const PROVIDER_CONFIG = {
    groq: {
        name: 'Groq',
        keyEnv: 'GROQ_API_KEY',
        modelEnv: 'GROQ_MODEL',
        defaultModel: 'llama-3.3-70b-versatile',
        url: 'https://api.groq.com/openai/v1/chat/completions'
    },
    anthropic: {
        name: 'Anthropic Claude',
        keyEnv: 'ANTHROPIC_API_KEY',
        modelEnv: 'ANTHROPIC_MODEL',
        defaultModel: 'claude-3-5-sonnet-20241022',
        url: 'https://api.anthropic.com/v1/messages'
    },
    openai: {
        name: 'OpenAI GPT',
        keyEnv: 'OPENAI_API_KEY',
        modelEnv: 'OPENAI_MODEL',
        defaultModel: 'gpt-4o',
        url: 'https://api.openai.com/v1/chat/completions'
    },
    gemini: {
        name: 'Google Gemini',
        keyEnv: 'GEMINI_API_KEY',
        modelEnv: 'GEMINI_MODEL',
        defaultModel: 'gemini-1.5-flash',
        url: 'https://generativelanguage.googleapis.com/v1/models'
    },
    mistral: {
        name: 'Mistral AI',
        keyEnv: 'MISTRAL_API_KEY',
        modelEnv: 'MISTRAL_MODEL',
        defaultModel: 'mistral-large-latest',
        url: 'https://api.mistral.ai/v1/chat/completions'
    },
    ollama: {
        name: 'Ollama (Local)',
        keyEnv: 'OLLAMA_API_KEY',
        modelEnv: 'OLLAMA_MODEL',
        defaultModel: 'llama3',
        url: 'http://localhost:11434/api/chat'
    },
    deepseek: {
        name: 'DeepSeek',
        keyEnv: 'DEEPSEEK_API_KEY',
        modelEnv: 'DEEPSEEK_MODEL',
        defaultModel: 'deepseek-chat',
        url: 'https://api.deepseek.com/v1/chat/completions'
    },
    azure: {
        name: 'Azure OpenAI',
        keyEnv: 'AZURE_OPENAI_KEY',
        modelEnv: 'AZURE_OPENAI_MODEL',
        defaultModel: 'gpt-4',
        url: null // Uses Azure endpoint
    },
    cohere: {
        name: 'Cohere',
        keyEnv: 'COHERE_API_KEY',
        modelEnv: 'COHERE_MODEL',
        defaultModel: 'command-r-plus',
        url: 'https://api.cohere.ai/v1/chat'
    },
    fireworks: {
        name: 'Fireworks AI',
        keyEnv: 'FIREWORKS_API_KEY',
        modelEnv: 'FIREWORKS_MODEL',
        defaultModel: 'accounts/fireworks/models/llama-v3-70b-instruct',
        url: 'https://api.fireworks.ai/v1/chat/completions'
    },
    together: {
        name: 'Together AI',
        keyEnv: 'TOGETHER_API_KEY',
        modelEnv: 'TOGETHER_MODEL',
        defaultModel: 'meta-llama/Llama-3.3-70B-Instruct-Turbo',
        url: 'https://api.together.xyz/v1/chat/completions'
    },
    cloudflare: {
        name: 'Cloudflare Workers AI',
        keyEnv: 'CLOUDFLARE_API_KEY',
        modelEnv: 'CLOUDFLARE_MODEL',
        defaultModel: '@cf/meta/llama-3.1-70b-instruct',
        url: 'https://api.cloudflare.com/client/v4/accounts'
    },
    Cerebras: {
        name: 'Cerebras',
        keyEnv: 'CEREBRAS_API_KEY',
        modelEnv: 'CEREBRAS_MODEL',
        defaultModel: 'llama-3.3-70b',
        url: 'https://api.cerebras.ai/v1/chat/completions'
    }
};

// Get available models for a provider
function getModelsForProvider(provider) {
    const models = {
        groq: [
            { id: 'llama-3.3-70b-versatile', name: 'Llama 3.3 70B (Fast)' },
            { id: 'llama-3.1-70b-instruct', name: 'Llama 3.1 70B' },
            { id: 'llama-3.2-90b-versatile', name: 'Llama 3.2 90B' },
            { id: 'mixtral-8x7b-32768', name: 'Mixtral 8x7B' },
            { id: 'gemma2-9b-it', name: 'Gemma 2 9B' }
        ],
        anthropic: [
            { id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet (Latest)' },
            { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus' },
            { id: 'claude-3-sonnet-20240229', name: 'Claude 3 Sonnet' },
            { id: 'claude-3-haiku-20240307', name: 'Claude 3 Haiku (Fast)' }
        ],
        openai: [
            { id: 'gpt-4o', name: 'GPT-4o (Latest)' },
            { id: 'gpt-4o-mini', name: 'GPT-4o Mini (Fast)' },
            { id: 'gpt-4-turbo', name: 'GPT-4 Turbo' },
            { id: 'gpt-4', name: 'GPT-4' },
            { id: 'gpt-3.5-turbo', name: 'GPT-3.5 Turbo (Fast)' }
        ],
        gemini: [
            { id: 'gemini-1.5-flash-latest', name: 'Gemini 1.5 Flash (Fast)' },
            { id: 'gemini-1.5-pro-latest', name: 'Gemini 1.5 Pro' },
            { id: 'gemini-2.0-flash-exp', name: 'Gemini 2.0 Flash' }
        ],
        mistral: [
            { id: 'mistral-large-latest', name: 'Mistral Large' },
            { id: 'mistral-small-latest', name: 'Mistral Small' },
            { id: 'mistral-medium-latest', name: 'Mistral Medium' }
        ],
        ollama: [
            { id: 'llama3', name: 'Llama 3' },
            { id: 'llama3.1', name: 'Llama 3.1' },
            { id: 'mistral', name: 'Mistral' },
            { id: 'phi3', name: 'Phi-3' },
            { id: 'codellama', name: 'CodeLlama' },
            { id: 'qwen2.5', name: 'Qwen 2.5' }
        ],
        deepseek: [
            { id: 'deepseek-chat', name: 'DeepSeek Chat' },
            { id: 'deepseek-coder', name: 'DeepSeek Coder' }
        ],
        cohere: [
            { id: 'command-r-plus', name: 'Command R+' },
            { id: 'command-r', name: 'Command R' }
        ],
        fireworks: [
            { id: 'accounts/fireworks/models/llama-v3-70b-instruct', name: 'Llama 3 70B' },
            { id: 'accounts/fireworks/models/qwen2-72b-instruct', name: 'Qwen 2 72B' }
        ],
        together: [
            { id: 'meta-llama/Llama-3.3-70B-Instruct-Turbo', name: 'Llama 3.3 70B' },
            { id: 'meta-llama/Llama-3.1-70B-Instruct-Turbo', name: 'Llama 3.1 70B' },
            { id: 'mistralai/Mistral-7B-Instruct-v0.2', name: 'Mistral 7B' }
        ],
        cloudflare: [
            { id: '@cf/meta/llama-3.1-70b-instruct', name: 'Llama 3.1 70B' },
            { id: '@cf/meta/llama-3.1-8b-instruct', name: 'Llama 3.1 8B' },
            { id: '@cf/deepseek/chat', name: 'DeepSeek' }
        ],
        Cerebras: [
            { id: 'llama-3.3-70b', name: 'Llama 3.3 70B (Ultra Fast)' }
        ]
    };
    return models[provider] || [];
}

// GET /api/settings/ai - Get current AI settings
router.get('/ai', (req, res) => {
    const provider = aiSettings.provider || 'groq';
    const config = PROVIDER_CONFIG[provider] || PROVIDER_CONFIG.groq;
    
    // Get current API key from env if available
    const envKey = process.env[config.keyEnv] || '';
    const hasStoredKey = envKey && !envKey.startsWith('your-') && envKey.length > 10;
    
    res.json({
        success: true,
        provider: aiSettings.provider,
        model: aiSettings.model || config.defaultModel,
        hasApiKey: hasStoredKey || aiSettings.apiKey.length > 0,
        availableProviders: Object.entries(PROVIDER_CONFIG).map(([key, val]) => ({
            id: key,
            name: val.name,
            hasKey: process.env[val.keyEnv] && !process.env[val.keyEnv].startsWith('your-') && process.env[val.keyEnv].length > 10
        })),
        availableModels: getModelsForProvider(provider),
        currentConfig: config
    });
});

// PUT /api/settings/ai - Update AI settings
router.put('/ai', (req, res) => {
    try {
        const { provider, apiKey, model, customUrl } = req.body;
        
        if (provider && PROVIDER_CONFIG[provider]) {
            aiSettings.provider = provider;
        }
        
        if (model) {
            aiSettings.model = model;
        }
        
        if (apiKey) {
            aiSettings.apiKey = apiKey;
        }
        
        if (customUrl) {
            aiSettings.customUrl = customUrl;
        }
        
        aiEngine.setAISettings(aiSettings);
        
        console.log('[AI Settings] Updated:', { provider: aiSettings.provider, model: aiSettings.model });
        
        res.json({
            success: true,
            message: 'AI settings updated',
            settings: {
                provider: aiSettings.provider,
                model: aiSettings.model || PROVIDER_CONFIG[aiSettings.provider]?.defaultModel
            }
        });
        
    } catch (err) {
        console.error('[AI Settings] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/settings/ai/test - Test AI connection
router.post('/ai/test', async (req, res) => {
    try {
        const { provider, apiKey, model } = req.body;
        const config = PROVIDER_CONFIG[provider];
        
        if (!config) {
            return res.status(400).json({ error: 'Unknown provider' });
        }
        
        const key = apiKey || process.env[config.keyEnv];
        if (!key || key.startsWith('your-')) {
            return res.status(400).json({ error: 'API key not configured' });
        }
        
        // Test based on provider
        let testResult = { success: false, message: '' };
        
        if (provider === 'groq') {
            const resp = await fetch(config.url, {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + key,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: model || config.defaultModel,
                    messages: [{ role: 'user', content: 'Hi' }],
                    max_tokens: 5
                })
            });
            if (resp.ok) testResult = { success: true, message: 'Connection successful!' };
            else testResult = { success: false, message: 'API error: ' + resp.status };
        }
        else if (provider === 'anthropic') {
            const resp = await fetch(config.url, {
                method: 'POST',
                headers: {
                    'x-api-key': key,
                    'anthropic-version': '2023-06-01',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: model || config.defaultModel,
                    max_tokens: 5,
                    messages: [{ role: 'user', content: 'Hi' }]
                })
            });
            if (resp.ok) testResult = { success: true, message: 'Connection successful!' };
            else testResult = { success: false, message: 'API error: ' + resp.status };
        }
        else if (provider === 'openai') {
            const resp = await fetch(config.url, {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + key,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: model || config.defaultModel,
                    messages: [{ role: 'user', content: 'Hi' }],
                    max_tokens: 5
                })
            });
            if (resp.ok) testResult = { success: true, message: 'Connection successful!' };
            else testResult = { success: false, message: 'API error: ' + resp.status };
        }
        else if (provider === 'gemini') {
            const resp = await fetch(`${config.url}/${model || config.defaultModel}:generateContent?key=${key}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: 'Hi' }] }]
                })
            });
            if (resp.ok) testResult = { success: true, message: 'Connection successful!' };
            else testResult = { success: false, message: 'API error: ' + resp.status };
        }
        else if (provider === 'ollama') {
            const url = aiSettings.customUrl || config.url;
            const resp = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: model || config.defaultModel,
                    messages: [{ role: 'user', content: 'Hi' }],
                    stream: false
                })
            });
            if (resp.ok) testResult = { success: true, message: 'Connected to Ollama!' };
            else testResult = { success: false, message: 'Ollama not running or error: ' + resp.status };
        }
        else {
            testResult = { success: false, message: 'Test not implemented for this provider' };
        }
        
        res.json(testResult);
        
    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});

// GET /api/settings - Get all non-sensitive settings
router.get('/', (req, res) => {
    res.json({
        success: true,
        ai: {
            provider: aiSettings.provider,
            model: aiSettings.model
        }
    });
});

module.exports = router;