from anthropic import Anthropic
from openai import OpenAI


def ask(prompt):
    return Anthropic().messages.create(model="x", max_tokens=10, messages=[{"role": "user", "content": prompt}])


def ask2(prompt):
    return OpenAI().chat.completions.create(model="x", messages=[{"role": "user", "content": prompt}])
