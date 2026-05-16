import yaml
from attacker import Attacker
from defenses import DefenseManager
from judge import Judge
from reporter import Reporter

def load_config():
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def choose_attack_type():
    print("\n请选择攻击类型：")
    types = {
        "1": "injection",
        "2": "disclosure",
        "3": "unsafe_output",
        "4": "agency",
        "5": "sysprompt_leak",
        "6": "all"
    }
    for k, v in types.items():
        print(f"{k}. {v}")
    choice = input("输入编号：").strip()
    return types.get(choice, "all")

def main():
    # 每条策略重复测试次数
    REPEAT_COUNT = 3

    config = load_config()
    attack_type = choose_attack_type()
    attacker = Attacker(config)

    use_defense = input("\n是否开启防御？(y/n)：").strip().lower()
    defense_manager = DefenseManager(config) if use_defense == 'y' else None
    if defense_manager:
        defense_manager.choose_defenses()

    if attack_type == "all":
        type_list = ["injection", "disclosure", "unsafe_output", "agency", "sysprompt_leak"]
    else:
        type_list = [attack_type]

    reporter = Reporter()
    original_system_prompt = config.get("system_prompt", "你是一个有用的AI助手。")

    for at in type_list:
        try:
            strategies = attacker.load_templates(at)
        except FileNotFoundError:
            print(f"警告：模板文件 templates/{at}.yaml 未找到，跳过")
            continue

        for strategy in strategies:
            name = strategy['name']
            user_prompt = strategy['user_prompt']
            print(f"\n[*] 测试策略：{name}")

            # ---------- 防御预处理 ----------
            blocked = False
            current_system_prompt = original_system_prompt
            processed_prompt = user_prompt   # 默认原样

            if defense_manager:
                # 输入防御
                processed_prompt, input_error = defense_manager.apply_input_defense(user_prompt)
                if input_error:
                    print(f"    [防御] 输入拦截: {input_error}")
                    # 被拦截，记录结果并跳过发送
                    reporter.add_result(name, breached=False, success_rate=0.0, blocked=True, reason=input_error)
                    continue   # 不再发送给模型
                user_prompt = processed_prompt
                
                # 系统提示防御
                current_system_prompt = defense_manager.apply_system_defense(current_system_prompt)
            # ---------------------------------

            success_count = 0
            total_count = 0
            last_response = ""
            blocked_by_output = False

            for i in range(REPEAT_COUNT):
                print(f"    第 {i+1}/{REPEAT_COUNT} 次测试...", end="", flush=True)
                response, error = attacker.send_attack(current_system_prompt, user_prompt)

                if error:
                    print(f" [错误] {error}")
                    total_count += 1
                    continue

                # 输出审查
                if defense_manager and "output_guard" in defense_manager.active_modes:
                    blocked_flag, msg = defense_manager.apply_output_guard(response)
                    if blocked_flag:
                        print(f" [防御] {msg}")
                        blocked_by_output = True
                        total_count += 1
                        continue

                judge = Judge(at)
                breached = judge.is_breach(user_prompt, response)
                total_count += 1
                if breached:
                    success_count += 1
                    print(" ❌ 攻破")
                else:
                    print(" ✅ 安全")
                last_response = response

            # 如果被输出拦截，视为整体被拦截（不计算成功率，显示拦截）
            if blocked_by_output:
                reporter.add_result(name, breached=False, success_rate=0.0, blocked=True, reason="输出拦截")
            else:
                success_rate = success_count / total_count if total_count > 0 else 0.0
                reporter.add_result(name, breached=success_count > 0, success_rate=success_rate, blocked=False)

            if last_response and not blocked_by_output:
                print(f"    响应预览: {last_response[:600]}...")
            if not blocked_by_output:
                print(f"    攻破统计: {success_count}/{total_count} 次成功，成功率 {success_rate*100:.0f}%")

    reporter.print_report()

if __name__ == "__main__":
    main()