import yaml
import os
import time
from openai import OpenAI

class Attacker:
    def __init__(self, config):
        self.config = config
        ollama_cfg = config['ollama']
        self.client = OpenAI(
            base_url=ollama_cfg['api_base'],
            api_key=ollama_cfg['api_key']
        )
        self.model = ollama_cfg['model']
        self.temperature = config.get('temperature', 0)
        self.max_tokens = config.get('max_tokens', 512)

    def load_templates(self, attack_type):
        template_dir = "templates"
        filename = os.path.join(template_dir, f"{attack_type}.yaml")
        with open(filename, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("strategies", [])

    def send_attack(self, system_prompt, user_prompt):
        """
        发送攻击请求，不再包含防御逻辑（防御由 DefenseManager 预处理）
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        try:
            print("    [等待 Ollama 响应中...]", end="", flush=True)
            start = time.time()
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=120.0
            )
            elapsed = time.time() - start
            print(f" 完成 ({elapsed:.1f}s)")
            content = response.choices[0].message.content
            return content, None
        except Exception as e:
            print(" 失败")
            return None, f"请求失败: {str(e)}"