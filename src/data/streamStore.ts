type Listener<T> = (value: T) => void;

export class StreamStore<T> {
  private listeners: Map<string, Listener<T>> = new Map();
  private latestValue: T;

  constructor(initialValue: T) {
    this.latestValue = initialValue;
  }

  subscribe(callback: Listener<T>): () => void {
    const id = Math.random().toString(36).slice(2);
    this.listeners.set(id, callback);
    callback(this.latestValue);
    return () => {
      this.listeners.delete(id);
    };
  }

  publish(value: T): void {
    this.latestValue = value;
    this.listeners.forEach((listener) => listener(value));
  }

  get current(): T {
    return this.latestValue;
  }
}